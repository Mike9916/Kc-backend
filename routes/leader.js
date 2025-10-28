// backend/routes/leader.js
const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const ExcelJS = require('exceljs');

const DATA_DIR = path.join(__dirname, '..', 'data');
async function readJSON(name, fallback) {
  try { return JSON.parse(await fs.readFile(path.join(DATA_DIR, name), 'utf8')); }
  catch (e) { if (e.code === 'ENOENT') return fallback; throw e; }
}
async function writeJSON(name, data) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.writeFile(path.join(DATA_DIR, name), JSON.stringify(data, null, 2));
}
function requireAuth(req, res, next){
  if (!req.auth) return res.status(401).json({ ok:false, error:'Unauthorized' });
  next();
}

const ROLE_CHAIN = ['GYJN','JYJN','WEJANM','NEMOBU','CHMN','DNGSN'];
const nextRole = (r) => ROLE_CHAIN[ROLE_CHAIN.indexOf(r)+1] || null;

/* --------------------------------- helpers --------------------------------- */
function compactEvangelism(r) {
  if (!r) return '';
  if (!r.participated) return 'Not Participated';
  const f = (n)=>Number(n||0);
  return `(findings:${f(r.findings)}, nfp:${f(r.nfp)}, rp:${f(r.rp)}, bb:${f(r.bb)})`;
}
function compactServiceEdu(r) {
  if (!r) return '';
  if (r.notAttended) return 'Not Attended';
  if (r.method === 'other' && r.realization) return `Other (${r.realization})`;
  if (r.method === 'other') return 'Other';
  if (r.method === 'physical') return 'Physical';
  if (r.method === 'online') return 'Online';
  return '';
}
function compactOffering(r) {
  if (!r) return '';
  if (r.notOffered) return 'Not Offered';
  const ch = r.channel || '—';
  const amt = (r.amount!=null)? r.amount : '—';
  return `Offered (method:${ch}, amount:${amt})`;
}
function saintRowToExport(member, rByType) {
  return [
    member.name || '',
    member.id || member.scjId || '',
    member.phone || '',
    member.center || member.jyk || '',
    member.cell || '',
    compactServiceEdu(rByType.service),
    compactServiceEdu(rByType.education),
    compactOffering(rByType.offering),
    compactEvangelism(rByType.evangelism),
  ];
}

/** Find reports by ownerId (saint id) + date + type */
function indexReportsByOwner(reports, date) {
  const byOwner = {};
  for (const r of reports) {
    if (r.scjDate !== date) continue;
    if (!byOwner[r.ownerId]) byOwner[r.ownerId] = {};
    byOwner[r.ownerId][r.type] = r;
  }
  return byOwner;
}

/** Scope filter: return members inside this leader's scope */
function filterMembersByScope(allMembers, role, scope) {
  // scope may contain { department, centers:[], cells:[] }
  if (role === 'GYJN') {
    const { cells=[] } = scope || {};
    return allMembers.filter(m => cells.length ? cells.includes(m.cell) : true);
  }
  if (role === 'JYJN') {
    const { centers=[] , department } = scope || {};
    return allMembers.filter(m =>
      (department ? m.department === department : true) &&
      (centers.length ? centers.includes(m.center) : true)
    );
  }
  if (role === 'WEJANM') {
    const { department } = scope || {};
    return allMembers.filter(m => department ? m.department === department : true);
  }
  // NEMOBU/CHMN/DNGSN/Admin see all saints
  return allMembers;
}

/** Roll up rows according to role (GYJN=saints; JYJN=cells; WEJANM=JYK; NEMOBU=departments; CHMN=NEMOBU; DNGSN=CHMN) */
function rollupRows(role, members, rByOwner) {
  if (role === 'GYJN') {
    // One row per saint
    return members.map(m => {
      const r = rByOwner[m.id] || {};
      const status = (r.service||r.education||r.evangelism||r.offering) ? 'Submitted' : 'Missing';
      return {
        kind:'saint',
        id: m.id, name: m.name, contact: { phone:m.phone, email:m.email },
        service: r.service, education: r.education, evangelism: r.evangelism, offering: r.offering,
        status, displayName: m.name
      };
    });
  }

  // Groupers
  const map = new Map();
  function add(groupKey, displayName, member, r) {
    if (!map.has(groupKey)) map.set(groupKey, {
      kind:'group', id:groupKey, displayName, members:[], agg:{}
    });
    const g = map.get(groupKey);
    g.members.push(member);
    // aggregate simple counts / sums
    if (r.service) {
      g.agg.svc = g.agg.svc || { physical:0, online:0, other:0, not:0, submitted:0 };
      if (r.service.notAttended) g.agg.svc.not++;
      else if (r.service.method === 'physical') g.agg.svc.physical++;
      else if (r.service.method === 'online') g.agg.svc.online++;
      else g.agg.svc.other++;
      g.agg.svc.submitted++;
    }
    if (r.education) {
      g.agg.edu = g.agg.edu || { physical:0, online:0, other:0, not:0, submitted:0 };
      if (r.education.notAttended) g.agg.edu.not++;
      else if (r.education.method === 'physical') g.agg.edu.physical++;
      else if (r.education.method === 'online') g.agg.edu.online++;
      else g.agg.edu.other++;
      g.agg.edu.submitted++;
    }
    if (r.evangelism) {
      g.agg.evg = g.agg.evg || { participated:0, findings:0, nfp:0, rp:0, bb:0, submitted:0 };
      if (r.evangelism.participated) g.agg.evg.participated++;
      g.agg.evg.findings += Number(r.evangelism.findings||0);
      g.agg.evg.nfp += Number(r.evangelism.nfp||0);
      g.agg.evg.rp  += Number(r.evangelism.rp||0);
      g.agg.evg.bb  += Number(r.evangelism.bb||0);
      g.agg.evg.submitted++;
    }
    if (r.offering) {
      g.agg.off = g.agg.off || { offered:0, notOffered:0, amount:0, submitted:0, via:{} };
      if (r.offering.notOffered) g.agg.off.notOffered++;
      else {
        g.agg.off.offered++;
        g.agg.off.amount += Number(r.offering.amount||0);
        const ch = r.offering.channel||'other';
        g.agg.off.via[ch] = (g.agg.off.via[ch]||0) + 1;
      }
      g.agg.off.submitted++;
    }
  }

  for (const m of members) {
    const r = rByOwner[m.id] || {};
    if (role === 'JYJN') {
      const key = `${m.center}::${m.cell}`;
      add(key, `${m.cell} (${m.leaderIds?.gyjn || 'GYJN'})`, m, r);
    } else if (role === 'WEJANM') {
      const key = `${m.center}`;
      add(key, `${m.center} ${m.department?.slice(0,1) ? '(' + m.department + ')' : ''}`.trim(), m, r);
    } else if (role === 'NEMOBU') {
      const key = `${m.department||'Unknown'}`;
      add(key, `${key} (${m.leaderIds?.wejanm || 'WEJANM'})`, m, r);
    } else if (role === 'CHMN') {
      const key = 'CHMN';
      add(key, `CHMN (${m.leaderIds?.nemobu || 'NEMOBU'})`, m, r);
    } else if (role === 'DNGSN' || role === 'Admin') {
      const key = 'DNGSN';
      add(key, `DNGSN (${m.leaderIds?.chmn || 'CHMN'})`, m, r);
    }
  }

  return [...map.values()].map(g => {
    const status = (g.agg.svc||g.agg.edu||g.agg.evg||g.agg.off) ? 'Submitted' : 'Missing';
    return { ...g, status };
  });
}

/* -------- workflow (per-day attempts + verify/return) -------- */
function wfKey(role, userId, date, type){
  return `${role}::${userId}::${date}::${type}`;
}
async function readWF(){
  const obj = await readJSON('leader_workflow.json', {});
  return obj || {};
}
async function writeWF(obj){
  await writeJSON('leader_workflow.json', obj || {});
}
function isReviewer(role){
  const r = (role||'').toUpperCase();
  return ['JYJN','WEJANM','NEMOBU','CHMN','DNGSN','ADMIN'].includes(r);
}
async function resolveNextLeader(role, scope){
  const toRole = nextRole(role);
  if (!toRole) return { role:null, name:null };
  const users = await readJSON('users.json', []);
  // naive match: same department and/or center if present
  let candidates = users.filter(u => (u.role||'').toUpperCase() === toRole);
  if (scope?.department) candidates = candidates.filter(u => (u.scope?.department||u.department) === scope.department);
  if (scope?.centers?.length) candidates = candidates.filter(u => !u.scope?.centers || u.scope.centers.some(c=>scope.centers.includes(c)));
  const name = candidates[0]?.name || null;
  return { role: toRole, name };
}

/* ------------------------------- router impl ------------------------------- */
module.exports = () => {
  const router = express.Router();

  // Summary (date + type)
  router.get('/summary', requireAuth, async (req, res, next) => {
    try {
      const { date, type } = req.query;
      if (!date || !type) return res.status(400).json({ ok:false, error:'date and type required' });

      const membersAll = await readJSON('members.json', []);
      const reports = await readJSON('reports.json', []);

      // saints only in rows/totals/warnings
      const saintsOnly = membersAll.filter(m => (m.role || '').toUpperCase() === 'SAINT');

      const scopedMembers = filterMembersByScope(saintsOnly, req.auth.role, req.auth.scope);
      const rByOwner = indexReportsByOwner(reports.filter(r => r.type===type), date);

      // Build rows based on role
      const rows = rollupRows(req.auth.role, scopedMembers, rByOwner);

      // Totals (computed only on saint rows)
      const totals = { count: rows.length };
      if (['service','education'].includes(type)) {
        let reported = 0, membersCount = 0, notAtt = 0, physical = 0, online = 0, other = 0;
        if (req.auth.role === 'GYJN') {
          membersCount = rows.length;
          for (const r of rows) {
            const item = (type==='service'? r.service : r.education);
            if (item) {
              reported++;
              if (item.notAttended) notAtt++;
              else if (item.method === 'physical') physical++;
              else if (item.method === 'online') online++;
              else other++;
            }
          }
        }
        totals.members = membersCount;
        totals.reported = reported;
        totals.missing = Math.max(0, membersCount - reported);
        totals.byMethod = { physical, online, other, not:notAtt };
        totals.attendancePct = membersCount ? Number(((reported - notAtt) / membersCount * 100).toFixed(1)) : 0;
      } else if (type === 'offering') {
        let amount = 0, offered = 0, notOffered = 0;
        if (req.auth.role === 'GYJN') {
          for (const r of rows) {
            if (r.offering) {
              if (r.offering.notOffered) notOffered++;
              else { offered++; amount += Number(r.offering.amount||0); }
            }
          }
        }
        totals.amount = amount; totals.offered = offered; totals.notOffered = notOffered;
      } else if (type === 'evangelism') {
        let participated = 0, findings=0, nfp=0, rp=0, bb=0;
        if (req.auth.role === 'GYJN') {
          for (const r of rows) {
            if (r.evangelism) {
              if (r.evangelism.participated) participated++;
              findings += Number(r.evangelism.findings||0);
              nfp += Number(r.evangelism.nfp||0);
              rp  += Number(r.evangelism.rp||0);
              bb  += Number(r.evangelism.bb||0);
            }
          }
        }
        totals.participated = participated; totals.findings = findings; totals.nfp = nfp; totals.rp = rp; totals.bb = bb;
      }

      // Warnings
      const warnings = [];
      for (const m of scopedMembers) {
        if (!m.center || !m.department || !m.cell) {
          warnings.push(`Missing mapping for ${m.name || m.id} (center/department/cell)`);
        }
      }

      // Workflow (per-day attempts)
      const wfAll = await readWF();
      const key = wfKey(req.auth.role, req.auth.user?.id || 'unknown', date, type);
      const wf = wfAll[key] || { date, forwardAttempts:0, status:'Open', returns:0 };
      const reviewer = isReviewer(req.auth.role);
      const needsVerify = reviewer && wf.status !== 'Verified';

      // Forward target (role + name)
      const forwardTo = await resolveNextLeader(req.auth.role, req.auth.scope || {});

      res.json({
        ok:true,
        role:req.auth.role,
        scopeLabel: req.auth.scope?.label || '',
        totals, warnings, rows,
        workflow: { date, forwardAttempts: wf.forwardAttempts||0, status: wf.status||'Open', returns: wf.returns||0, needsVerify },
        forwardTo
      });
    } catch (e) { next(e); }
  });

  // GYJN fill-missing → writes report as if saint submitted
  router.post('/reports/:type', requireAuth, async (req, res, next) => {
    try {
      if (!['GYJN','Admin'].includes(req.auth.role))
        return res.status(403).json({ ok:false, error:'Only GYJN can fill missing' });

      const type = req.params.type;
      const { scjId, scjDate, ...body } = req.body || {};
      if (!scjId || !scjDate) return res.status(400).json({ ok:false, error:'scjId and scjDate required' });

      const membersAll = await readJSON('members.json', []);
      const saintsOnly = membersAll.filter(m => (m.role || '').toUpperCase() === 'SAINT');
      const inScope = filterMembersByScope(saintsOnly, req.auth.role, req.auth.scope).some(m => (m.id===scjId || m.scjId===scjId));
      if (!inScope) return res.status(403).json({ ok:false, error:'Outside your scope' });

      const reports = await readJSON('reports.json', []);
      const existing = reports.find(r => r.ownerId===scjId && r.type===type && r.scjDate===scjDate);
      if (existing) return res.status(409).json({ ok:false, error:'Already submitted' });

      // Normalize evangelism + offering semantics (same rules as saints)
      if (type === 'evangelism') {
        const participated = !!body.participated;
        body.participated = participated;
        body.findings = participated ? Number(body.findings||0) : 0;
        body.nfp      = participated ? Number(body.nfp||0) : 0;
        body.rp       = participated ? Number(body.rp||0)  : 0;
        body.bb       = participated ? Number(body.bb||0)  : 0;
        body.summary  = participated ? (body.summary || 'Participated in evangelism')
                                     : 'Did not participate';
      }
      if (type === 'offering') {
        body.notOffered = !!body.notOffered;
        if (body.notOffered) { body.channel = null; body.amount = 0; }
        else { body.amount = Number(body.amount||0); }
      }

      const rec = {
        id: 'R-' + Date.now(),
        type, period: null,
        scjDate,
        ownerId: scjId,
        status: 'Submitted',
        attempts: 1,
        lastSubmittedAt: new Date().toISOString(),
        history: [{ ts: new Date().toISOString(), action:'SUBMIT_BY_LEADER', by:req.auth.user?.id }],
        ...body
      };
      reports.push(rec);
      await writeJSON('reports.json', reports);

      // Audit
      const audit = await readJSON('audit.json', []);
      audit.push({ actor:req.auth.user?.id, role:req.auth.role, action:'LEADER_FILL_MISSING', payloadSummary:{ scjId, type, scjDate }, timestamp:new Date().toISOString() });
      await writeJSON('audit.json', audit);

      res.json({ ok:true, id:rec.id });
    } catch (e) { next(e); }
  });

  // Forward summary (respect per-day attempts; reviewers must verify first)
  router.post('/forward/:type', requireAuth, async (req, res, next) => {
    try {
      const { type } = req.params;
      const { scjDate, counts = {}, scopeLabel='' } = req.body || {};
      if (!scjDate) return res.status(400).json({ ok:false, error:'scjDate required' });

      const wfAll = await readWF();
      const key = wfKey(req.auth.role, req.auth.user?.id || 'unknown', scjDate, type);
      const wf = wfAll[key] || { date: scjDate, forwardAttempts: 0, status: 'Open', returns: 0 };

      const reviewer = isReviewer(req.auth.role);
      if (reviewer && wf.status !== 'Verified') {
        return res.status(409).json({ ok:false, error:'Verify first' });
      }
      if ((wf.forwardAttempts || 0) >= 3) {
        return res.status(429).json({ ok:false, error:'Attempt limit reached' });
      }

      // compute missing count for audit/record (best-effort) — saints only
      const members = await readJSON('members.json', []);
      const saintsOnly = members.filter(m => (m.role || '').toUpperCase() === 'SAINT');
      const reports = await readJSON('reports.json', []);
      const scopedMembers = filterMembersByScope(saintsOnly, req.auth.role, req.auth.scope);
      const byOwner = indexReportsByOwner(reports.filter(r => r.type===type), scjDate);
      let submitted = 0;
      for (const m of scopedMembers) if (byOwner[m.id]) submitted++;
      const missingCount = Math.max(0, scopedMembers.length - submitted);
      const incomplete = missingCount > 0;

      // append forward record
      const forwards = await readJSON('leader_forwards.json', []);
      forwards.push({
        id: 'FWD-' + Date.now(),
        fromRole: req.auth.role,
        toRole: nextRole(req.auth.role) || 'Final',
        fromId: req.auth.user?.id,
        date: scjDate,
        type,
        counts,
        scopeLabel,
        incomplete,
        missingCount,
        createdAt: new Date().toISOString()
      });
      await writeJSON('leader_forwards.json', forwards);

      // update workflow (increment attempt; keep status)
      wf.forwardAttempts = (wf.forwardAttempts || 0) + 1;
      wfAll[key] = wf;
      await writeWF(wfAll);

      // audit
      const audit = await readJSON('audit.json', []);
      audit.push({ actor:req.auth.user?.id, role:req.auth.role, action:'LEADER_FORWARD', payloadSummary:{ type, scjDate, incomplete, missingCount }, timestamp:new Date().toISOString() });
      await writeJSON('audit.json', audit);

      res.json({ ok:true, incomplete, missingCount, forwardAttempts: wf.forwardAttempts });
    } catch (e) { next(e); }
  });

  // Verify (reviewers only)
  router.post('/verify/:type', requireAuth, async (req, res, next) => {
    try {
      if (!isReviewer(req.auth.role)) return res.status(403).json({ ok:false, error:'Forbidden' });
      const { type } = req.params;
      const { scjDate } = req.body || {};
      if (!scjDate) return res.status(400).json({ ok:false, error:'scjDate required' });

      const wfAll = await readWF();
      const key = wfKey(req.auth.role, req.auth.user?.id || 'unknown', scjDate, type);
      const wf = wfAll[key] || { date: scjDate, forwardAttempts:0, status:'Open', returns:0 };
      wf.status = 'Verified';
      wfAll[key] = wf;
      await writeWF(wfAll);

      res.json({ ok:true, status:'Verified' });
    } catch (e) { next(e); }
  });

  // Return (reviewers only) — resets attempts
  router.post('/return/:type', requireAuth, async (req, res, next) => {
    try {
      if (!isReviewer(req.auth.role)) return res.status(403).json({ ok:false, error:'Forbidden' });
      const { type } = req.params;
      const { scjDate, note='' } = req.body || {};
      if (!scjDate) return res.status(400).json({ ok:false, error:'scjDate required' });

      const wfAll = await readWF();
      const key = wfKey(req.auth.role, req.auth.user?.id || 'unknown', scjDate, type);
      const wf = wfAll[key] || { date: scjDate, forwardAttempts:0, status:'Open', returns:0 };
      wf.status = 'Returned';
      wf.forwardAttempts = 0;
      wf.returns = (wf.returns || 0) + 1;
      wf.returnNote = note;
      wfAll[key] = wf;
      await writeWF(wfAll);

      // audit
      const audit = await readJSON('audit.json', []);
      audit.push({ actor:req.auth.user?.id, role:req.auth.role, action:'LEADER_RETURN', payloadSummary:{ type, scjDate, note }, timestamp:new Date().toISOString() });
      await writeJSON('audit.json', audit);

      res.json({ ok:true, status:'Returned' });
    } catch (e) { next(e); }
  });

  // CSV export (single sheet) — saints only
  router.get('/export.csv', requireAuth, async (req, res, next) => {
    try {
      const { date } = req.query;
      if (!date) return res.status(400).json({ ok:false, error:'date required' });

      const membersAll = await readJSON('members.json', []);
      const saintsOnly = membersAll.filter(m => (m.role || '').toUpperCase() === 'SAINT');
      const reports = await readJSON('reports.json', []);

      const scopedMembers = filterMembersByScope(saintsOnly, req.auth.role, req.auth.scope);
      const rByOwner = indexReportsByOwner(reports, date);

      const header = ['Name','SCJ ID','Phone','JYK','Cell group','Service','Education','Offering','Evangelism'];
      const rows = [header];
      for (const m of scopedMembers.sort((a,b)=>{
        const aK = `${a.center||''}|${a.cell||''}|${a.name||''}`;
        const bK = `${b.center||''}|${b.cell||''}|${b.name||''}`;
        return aK.localeCompare(bK);
      })) {
        const lines = saintRowToExport(m, {
          service: rByOwner[m.id]?.service,
          education: rByOwner[m.id]?.education,
          offering: rByOwner[m.id]?.offering,
          evangelism: rByOwner[m.id]?.evangelism
        });
        rows.push(lines);
      }

      const csv = rows.map(r=>r.map(v=>{
        const s = String(v ?? '');
        return s.includes(',') || s.includes('"') ? `"${s.replace(/"/g,'""')}"` : s;
      }).join(',')).join('\n');

      res.header('Content-Type','text/csv');
      res.header('Content-Disposition', `attachment; filename="kc_export_${req.auth.role}_${date}.csv"`);
      res.send(csv);
    } catch (e) { next(e); }
  });

  // XLSX export (multi-sheet) — saints only
  router.get('/export.xlsx', requireAuth, async (req, res, next) => {
    try {
      const { date, type } = req.query;
      if (!date) return res.status(400).json({ ok:false, error:'date required' });

      const membersAll = await readJSON('members.json', []);
      const saintsOnly = membersAll.filter(m => (m.role || '').toUpperCase() === 'SAINT');
      const reports = await readJSON('reports.json', []);
      const scopedMembers = filterMembersByScope(saintsOnly, req.auth.role, req.auth.scope);
      const rByOwner = indexReportsByOwner(reports, date);

      const wb = new ExcelJS.Workbook();
      wb.creator = 'KC App'; wb.created = new Date();

      const banner = `Exported by: ${req.auth.user?.name || ''} | Title: ${req.auth.role} | Date: ${date} | Type: ${type||'all'} | Generated: ${new Date().toISOString()}`;
      function addSheet(name, rows) {
        const ws = wb.addWorksheet(name);
        ws.addRow([banner]);
        ws.mergeCells('A1:I1');
        ws.getCell('A1').font = { bold:true };
        ws.addRow(['Name','SCJ ID','Phone','JYK','Cell group','Service','Education','Offering','Evangelism']).font = { bold:true };
        for (const r of rows) ws.addRow(r);
        ws.columns = [
          { width:24 }, { width:16 }, { width:16 }, { width:16 }, { width:22 },
          { width:26 }, { width:26 }, { width:28 }, { width:36 }
        ];
      }

      if (req.auth.role === 'GYJN') {
        const title = (req.auth.scope?.label || 'Cell').slice(0,28);
        const rows = scopedMembers.map(m => saintRowToExport(m, {
          service: rByOwner[m.id]?.service,
          education: rByOwner[m.id]?.education,
          offering: rByOwner[m.id]?.offering,
          evangelism: rByOwner[m.id]?.evangelism
        }));
        addSheet(title || 'Cell', rows);
      } else if (req.auth.role === 'JYJN') {
        const byCell = {};
        for (const m of scopedMembers) {
          const key = `${m.cell || 'Unknown'}`.slice(0,28);
          byCell[key] = byCell[key] || [];
          byCell[key].push(saintRowToExport(m, {
            service: rByOwner[m.id]?.service,
            education: rByOwner[m.id]?.education,
            offering: rByOwner[m.id]?.offering,
            evangelism: rByOwner[m.id]?.evangelism
          }));
        }
        for (const [cell, rows] of Object.entries(byCell)) addSheet(cell, rows);
      } else if (req.auth.role === 'WEJANM') {
        const byJyk = {};
        for (const m of scopedMembers) {
          const key = `${m.center || 'JYK'}`.slice(0,28);
          byJyk[key] = byJyk[key] || [];
          byJyk[key].push(saintRowToExport(m, {
            service: rByOwner[m.id]?.service,
            education: rByOwner[m.id]?.education,
            offering: rByOwner[m.id]?.offering,
            evangelism: rByOwner[m.id]?.evangelism
          }));
        }
        for (const [jyk, rows] of Object.entries(byJyk)) addSheet(jyk, rows);
      } else if (req.auth.role === 'NEMOBU') {
        const byDept = {};
        for (const m of scopedMembers) {
          const key = `${m.department || 'Dept'}`.slice(0,28);
          byDept[key] = byDept[key] || [];
          byDept[key].push(saintRowToExport(m, {
            service: rByOwner[m.id]?.service,
            education: rByOwner[m.id]?.education,
            offering: rByOwner[m.id]?.offering,
            evangelism: rByOwner[m.id]?.evangelism
          }));
        }
        for (const [dep, rows] of Object.entries(byDept)) addSheet(dep, rows);
      } else { // CHMN / DNGSN / Admin
        const rows = scopedMembers.map(m => saintRowToExport(m, {
          service: rByOwner[m.id]?.service,
          education: rByOwner[m.id]?.education,
          offering: rByOwner[m.id]?.offering,
          evangelism: rByOwner[m.id]?.evangelism
        }));
        addSheet(req.auth.role, rows);
      }

      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="kc_export_${req.auth.role}_${date}.xlsx"`);
      await wb.xlsx.write(res);
      res.end();
    } catch (e) { next(e); }
  });

  return router;
};