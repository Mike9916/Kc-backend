// routes/reports.js
module.exports = (app, { read, write, auth }) => {

  function save(type, record) {
    const files = {
      service: "reports_service.json",
      education: "reports_education.json",
      evangelism: "reports_evangelism.json",
      offering: "reports_offering.json",
    };
    const file = files[type];
    const arr = read(file, []);
    if (arr.some(r => r.scjId === record.scjId && r.scjDate === record.scjDate)) {
      const err = new Error("duplicate"); err.status = 409; throw err;
    }
    arr.push(record); write(file, arr); return record;
  }

  function n(v){ const x=Number(v); return (isFinite(x) && x>=0)? Math.floor(x):0; }

  // Each POST uses req.user.scjId; duplicates are per-type+date (not cross-type)
  app.post("/api/reports/service", auth, (req, res) => {
    try {
      const r = save("service", {
        id: "svc_"+Date.now(), scjId: req.user.scjId, scjDate: String(req.body.scjDate||""),
        method: String(req.body.method||"physical"), notAttended: !!req.body.notAttended,
        realization: String(req.body.realization||""), createdAt: new Date().toISOString()
      }); res.json({ ok:true, record:r });
    } catch(e){ res.status(e.status||400).json({ error:e.message||"error" }); }
  });

  app.post("/api/reports/education", auth, (req, res) => {
    try {
      const r = save("education", {
        id: "edu_"+Date.now(), scjId: req.user.scjId, scjDate: String(req.body.scjDate||""),
        session: String(req.body.session||"ALL_SUN").toUpperCase(),
        method: String(req.body.method||"physical"), notAttended: !!req.body.notAttended,
        realization: String(req.body.realization||""), createdAt: new Date().toISOString()
      }); res.json({ ok:true, record:r });
    } catch(e){ res.status(e.status||400).json({ error:e.message||"error" }); }
  });

  app.post("/api/reports/evangelism", auth, (req, res) => {
    try {
      const participated = !!req.body.participated;
      const r = save("evangelism", {
        id: "ev_"+Date.now(), scjId: req.user.scjId, scjDate: String(req.body.scjDate||""),
        participated, findings: participated?n(req.body.findings):0, nfp: participated?n(req.body.nfp):0,
        rp: participated?n(req.body.rp):0, bb: participated?n(req.body.bb):0, createdAt: new Date().toISOString(),
      }); res.json({ ok:true, record:r });
    } catch(e){ res.status(e.status||400).json({ error:e.message||"error" }); }
  });

  app.post("/api/reports/offering", auth, (req, res) => {
    try {
      const amount = Number(req.body.amount); if(!isFinite(amount)||amount<0) throw new Error("invalid amount");
      const r = save("offering", {
        id: "off_"+Date.now(), scjId: req.user.scjId, scjDate: String(req.body.scjDate||""),
        channel: String(req.body.channel||"cash"), amount, createdAt: new Date().toISOString(),
      }); res.json({ ok:true, record:r });
    } catch(e){ res.status(e.status||400).json({ error:e.message||"error" }); }
  });

  // Optional: list my reports
  app.get("/api/reports/my", auth, (req, res) => {
    const files = ["reports_service.json","reports_education.json","reports_evangelism.json","reports_offering.json"];
    const date = String(req.query.date||"");
    const out = {};
    for(const f of files){
      const key = f.split("_")[1].replace(".json","");
      const arr = read(f, []).filter(r => r.scjId===req.user.scjId && (!date || r.scjDate===date));
      out[key]=arr;
    }
    res.json(out);
  });
};