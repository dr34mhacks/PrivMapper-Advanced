"""Static CSS/JS assets embedded into the HTML report."""

CSS = """
:root{
  /* Black & Olive Green Theme - Gen Z Edition */
  --bg:#0a0a0a;--bg2:#111111;--bg3:#181818;--bg4:#222222;
  --bd:#2a2a2a;--bd2:#3a3a3a;--bd3:#444;
  --tx:#d4d4d4;--tx2:#8a8a8a;--txb:#f5f5f5;
  --primary:#84a98c;--primary-light:#1a2e1a;--primary-dark:#52796f;
  --cr:#ff6b6b;--cr2:#2a1515;--cr3:#4a1c1c;
  --hi:#fbbf24;--hi2:#2a2010;--hi3:#463d1a;
  --md:#60a5fa;--md2:#172554;--md3:#1e3a5f;
  --ok:#84a98c;--ok2:#1a2e1a;--ok3:#2d4a32;
  --ac:#84a98c;--ac2:#1a2e1a;--ac3:#2d4a32;
  --purple:#a78bfa;--purple2:#1e1a2e;--purple3:#3b2f5a;
  --sidebar:#0a0a0a;--sidebar-text:#8a8a8a;
  --olive:#84a98c;--olive-dark:#52796f;--olive-light:#cad2c5;--olive-bright:#a4c3ac;
  --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace;
  --body:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
  --shadow-sm:0 1px 2px rgba(0,0,0,0.3);
  --shadow:0 2px 8px rgba(0,0,0,0.4),0 1px 3px rgba(0,0,0,0.3);
  --shadow-lg:0 8px 24px rgba(0,0,0,0.5),0 4px 8px rgba(0,0,0,0.3);
  --shadow-glow:0 0 20px rgba(132,169,140,0.15);
  --radius:12px;--radius-sm:8px;--radius-lg:16px;--radius-xl:24px;
  /* Syntax highlighting */
  --syn-keyword:#ff79c6;--syn-string:#f1fa8c;--syn-comment:#6272a4;--syn-func:#50fa7b;--syn-var:#bd93f9;--syn-num:#ffb86c;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--body);background:var(--bg);color:var(--tx);font-size:14px;line-height:1.7;display:flex;min-height:100vh}
code{font-family:var(--mono);font-size:11px;background:var(--bg3);padding:3px 8px;border-radius:var(--radius-sm);color:var(--olive-bright);border:1px solid var(--bd)}
pre{font-family:var(--mono);font-size:12px;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);color:#e2e8f0;padding:20px;border-radius:var(--radius);overflow-x:auto;white-space:pre-wrap;margin:12px 0;border:1px solid #2a3a5a;position:relative}
pre::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--olive),var(--olive-dark));border-radius:var(--radius) var(--radius) 0 0}
p{margin-bottom:10px}
strong{color:var(--txb);font-weight:600}
h1,h2,h3,h4{color:var(--txb);font-weight:700;letter-spacing:-0.02em}

@keyframes fade-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes slide-up{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@keyframes glow{0%,100%{box-shadow:0 0 5px rgba(132,169,140,0.2)}50%{box-shadow:0 0 20px rgba(132,169,140,0.4)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.7}}

/* Sidebar - Dark Olive Theme */
.sidebar{width:240px;background:#0d0d0d;color:var(--sidebar-text);flex-shrink:0;position:fixed;height:100vh;overflow-y:auto;z-index:100;border-right:1px solid var(--bd)}
.sidebar::-webkit-scrollbar{width:4px}
.sidebar::-webkit-scrollbar-thumb{background:var(--olive-dark);border-radius:2px}
.sidebar-header{padding:20px;border-bottom:1px solid var(--bd)}
.sidebar-logo{font-size:15px;font-weight:600;color:var(--olive-light);display:flex;align-items:center;gap:10px}
.sidebar-logo-icon{width:32px;height:32px;background:var(--olive-dark);border-radius:var(--radius);display:flex;align-items:center;justify-content:center;font-size:16px}
.sidebar-version{font-size:10px;color:var(--tx2);margin-top:4px;font-family:var(--mono)}
.sidebar-nav{padding:12px 0}
.sidebar-section{padding:16px 16px 8px;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--olive-dark);font-weight:500}
.sidebar-link{display:flex;align-items:center;gap:10px;padding:10px 16px;color:var(--sidebar-text);text-decoration:none;font-size:13px;transition:all 0.15s;cursor:pointer;margin:2px 8px;border-radius:var(--radius)}
.sidebar-link:hover{background:var(--bg3);color:var(--olive-light)}
.sidebar-link.active{background:var(--olive-dark);color:#fff}
.sidebar-link-icon{width:18px;text-align:center;font-size:14px}
.sidebar-link-badge{margin-left:auto;font-size:10px;padding:2px 6px;background:var(--cr);color:#fff;border-radius:4px;font-family:var(--mono);font-weight:600}
.sidebar-stats{padding:16px;border-top:1px solid var(--bd);margin-top:auto}
.sidebar-stat{display:flex;justify-content:space-between;padding:6px 0;font-size:12px}
.sidebar-stat-label{color:var(--tx2)}
.sidebar-stat-value{color:var(--olive);font-family:var(--mono);font-weight:500}

.main-wrapper{flex:1;margin-left:240px;display:flex;flex-direction:column;min-height:100vh;background:linear-gradient(180deg,var(--bg) 0%,#0d100d 100%)}

/* Header - Modern Glass Effect */
.header{background:rgba(17,17,17,0.8);backdrop-filter:blur(12px);padding:20px 32px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--bd);position:sticky;top:0;z-index:50}
.header-inner{flex:1}
.header-label{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--olive);margin-bottom:4px;font-weight:600}
.header-title{font-size:22px;font-weight:800;color:var(--txb);letter-spacing:-0.03em}
.header-meta{font-size:12px;color:var(--tx2);margin-top:4px;font-family:var(--mono)}
.header-actions{display:flex;gap:10px}
.header-btn{font-size:12px;padding:10px 18px;background:var(--bg3);border:1px solid var(--bd);color:var(--tx);border-radius:var(--radius);cursor:pointer;transition:all 0.2s ease;font-weight:500}
.header-btn:hover{border-color:var(--olive);color:var(--olive);transform:translateY(-1px);box-shadow:var(--shadow)}
.header-badge{font-family:var(--mono);font-size:10px;padding:8px 14px;background:linear-gradient(135deg,var(--primary-light),var(--ok2));color:var(--olive-bright);border-radius:var(--radius);font-weight:600;border:1px solid var(--olive-dark)}

/* Main Content - Breathing Room */
.main{flex:1;padding:32px;overflow-y:auto;max-width:1500px;width:100%;box-sizing:border-box}
.content-section{display:none;animation:fade-in 0.3s ease}
.content-section.active{display:block}

/* Summary Cards - Modern Glass Cards */
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:32px}
.summary-card{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius-lg);padding:24px 20px;text-align:center;transition:all 0.25s ease;position:relative;overflow:hidden}
.summary-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--olive-dark),transparent);opacity:0;transition:opacity 0.3s}
.summary-card:hover{transform:translateY(-4px);box-shadow:var(--shadow-lg),var(--shadow-glow);border-color:var(--olive-dark)}
.summary-card:hover::before{opacity:1}
.summary-value{font-size:36px;font-weight:800;color:var(--olive-bright);font-family:var(--mono);letter-spacing:-0.02em}
.summary-value.critical{color:var(--cr);text-shadow:0 0 20px rgba(255,107,107,0.3)}
.summary-value.high{color:var(--hi);text-shadow:0 0 20px rgba(251,191,36,0.3)}
.summary-label{font-size:11px;color:var(--tx2);margin-top:8px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}

/* Findings Grid - Modern Card Layout */
.findings-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,380px),1fr));gap:20px}
.finding-card{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius-lg);overflow:hidden;transition:all 0.25s ease}
.finding-card:hover{box-shadow:var(--shadow-lg);border-color:var(--olive-dark);transform:translateY(-2px)}
.finding-card-header{padding:24px;display:flex;align-items:flex-start;justify-content:space-between;gap:16px}
.finding-card-title{font-size:15px;font-weight:700;color:var(--txb);line-height:1.5;flex:1}
.finding-card-body{padding:0 24px 24px}
.finding-card-desc{font-size:13px;color:var(--tx2);line-height:1.7;margin-bottom:16px}
.finding-card-meta{display:flex;flex-wrap:wrap;gap:10px}
.finding-card-tag{font-family:var(--mono);font-size:9px;padding:5px 12px;background:var(--bg4);border-radius:var(--radius-sm);color:var(--tx2);border:1px solid var(--bd)}
.finding-card-footer{padding:18px 24px;background:var(--bg4);border-top:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center}
.finding-card-action{font-family:var(--mono);font-size:11px;color:var(--olive);cursor:pointer;font-weight:600;display:flex;align-items:center;gap:8px;transition:all 0.2s}
.finding-card-action:hover{color:var(--olive-bright);transform:translateX(3px)}

/* Finding Detail - Expandable Cards */
.finding{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius-lg);margin-bottom:20px;overflow:hidden;transition:all 0.25s ease}
.finding:hover{border-color:var(--bd2)}
.finding-header{display:flex;justify-content:space-between;align-items:center;padding:20px 24px;cursor:pointer;transition:all 0.2s}
.finding-header:hover{background:rgba(132,169,140,0.05)}
.finding-header-left{display:flex;align-items:center;gap:16px}
.finding-chevron{font-size:12px;color:var(--tx2);transition:all 0.25s ease;width:20px;text-align:center}
.finding-chevron.open{transform:rotate(90deg);color:var(--olive)}
.finding-title{font-size:15px;font-weight:700;color:var(--txb)}
.finding-body{display:none;padding:24px;background:linear-gradient(180deg,var(--bg2),var(--bg));border-top:1px solid var(--bd)}
.finding-body.open{display:block;animation:fade-in 0.3s ease}
.finding-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:20px;margin-bottom:20px}
.finding-grid:last-child{margin-bottom:0}
@media(max-width:1200px){.finding-grid{grid-template-columns:1fr}.findings-grid{grid-template-columns:1fr}.query-grid{grid-template-columns:repeat(auto-fill,minmax(250px,1fr))}.overperm-grid{grid-template-columns:repeat(auto-fill,minmax(180px,1fr))}.run-info-grid{grid-template-columns:1fr}}
@media(max-width:900px){.sidebar{display:none}.main-wrapper{margin-left:0}.header{padding:16px 20px}.main{padding:20px}.summary-grid{grid-template-columns:repeat(2,1fr)}.principal-controls{flex-direction:column;align-items:stretch}.filter-group{justify-content:center}.export-group{justify-content:center}.graph-canvas{height:400px!important}}
@media(max-width:600px){.summary-grid{grid-template-columns:1fr}.header-title{font-size:18px}.finding-section h4{font-size:9px}.badge{font-size:8px;padding:3px 8px}.site-footer{flex-direction:column;gap:8px;text-align:center}.escalation-table{font-size:11px}.escalation-table th,.escalation-table td{padding:8px 6px}}

/* Tables - Responsive */
.table-wrapper{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:0 -4px;padding:0 4px}
.escalation-table{width:100%;min-width:600px}
.finding-section{background:var(--bg3);border-radius:var(--radius);padding:20px;border:1px solid var(--bd);transition:all 0.2s ease}
.finding-section:hover{border-color:var(--olive-dark);box-shadow:inset 0 0 0 1px rgba(132,169,140,0.1)}
.finding-section h4{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--olive);margin-bottom:14px;font-family:var(--mono);display:flex;align-items:center;gap:10px}
.finding-section h4::before{content:"";width:4px;height:14px;background:linear-gradient(180deg,var(--olive),var(--olive-dark));border-radius:2px}
.finding-section p{font-size:13px;line-height:1.7;color:var(--tx)}

/* Badges - Modern Pill Style */
.badge{font-family:var(--mono);font-size:9px;font-weight:700;padding:5px 12px;border-radius:20px;text-transform:uppercase;letter-spacing:0.8px;border:1px solid currentColor;transition:all 0.2s}
.badge.critical{background:linear-gradient(135deg,var(--cr2),#3a1a1a);color:#ff6b6b;border-color:#ff6b6b;box-shadow:0 0 10px rgba(255,107,107,0.2)}
.badge.high{background:linear-gradient(135deg,var(--hi2),#3a3010);color:#fbbf24;border-color:#fbbf24;box-shadow:0 0 10px rgba(251,191,36,0.2)}
.badge.medium{background:linear-gradient(135deg,var(--md2),#1a2a4a);color:#60a5fa;border-color:#60a5fa}
.badge.low{background:linear-gradient(135deg,var(--ok2),#1a3a2a);color:var(--olive-bright);border-color:var(--olive)}

/* Principal Tags - Clickable Pills */
.principal-list{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.principal-tag{font-family:var(--mono);font-size:10px;padding:6px 12px;background:var(--bg4);border-radius:var(--radius-sm);color:var(--tx);transition:all 0.2s ease;cursor:pointer;border:1px solid var(--bd)}
.principal-tag:hover{background:var(--olive-dark);color:#fff;border-color:var(--olive);transform:translateY(-1px);box-shadow:var(--shadow-sm)}
.principal-tag.critical{background:linear-gradient(135deg,var(--cr2),#3a1a1a);color:var(--cr);border-color:var(--cr3)}
.principal-tag.admin{background:linear-gradient(135deg,var(--cr2),#3a1a1a);color:var(--cr);border-color:var(--cr3)}

/* Affected Principals - Compact Card Grid */
.affected-principals{display:flex;flex-direction:column;gap:8px}
.affected-principals-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.affected-principals-actions{display:flex;gap:6px}
.principal-card{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius-sm);transition:all 0.15s;gap:12px}
.principal-card:hover{border-color:var(--olive-dark);background:var(--bg3)}
.principal-card-left{display:flex;align-items:center;gap:10px;flex:1;min-width:0}
.principal-card-icon{width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0}
.principal-card-icon.user{background:linear-gradient(135deg,var(--olive-dark),#2a4a3a);color:var(--olive-bright)}
.principal-card-icon.role{background:linear-gradient(135deg,#2a3a5a,#1a2a4a);color:#60a5fa}
.principal-card-info{flex:1;min-width:0}
.principal-card-name{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--txb);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.principal-card-arn{font-family:var(--mono);font-size:9px;color:var(--tx2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}
.principal-card-badges{display:flex;gap:4px;flex-shrink:0}
.principal-card-actions{display:flex;gap:4px;flex-shrink:0}
.copy-arn-btn{font-family:var(--mono);font-size:9px;padding:4px 8px;background:transparent;border:1px solid var(--bd);color:var(--tx2);border-radius:4px;cursor:pointer;transition:all 0.15s}
.copy-arn-btn:hover{background:var(--olive-dark);border-color:var(--olive);color:#fff}
.copy-arn-btn.copied{background:var(--olive);border-color:var(--olive);color:#000}
.show-more-btn{font-family:var(--mono);font-size:11px;padding:10px 16px;background:var(--bg3);border:1px dashed var(--bd);color:var(--tx2);border-radius:var(--radius-sm);cursor:pointer;transition:all 0.15s;width:100%;text-align:center;margin-top:8px}
.show-more-btn:hover{background:var(--olive-dark);border-color:var(--olive);border-style:solid;color:#fff}
.principals-hidden{display:none!important}
.principals-hidden.show{display:flex!important}
.overperm-chip.principals-hidden.show{display:flex!important}

/* Overly Permissive - Compact Chip View */
.overperm-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.overperm-chip{display:flex;align-items:center;gap:8px;padding:10px 12px;background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius-sm);transition:all 0.15s;cursor:pointer}
.overperm-chip:hover{border-color:var(--olive-dark);background:var(--bg3)}
.overperm-chip-icon{width:24px;height:24px;border-radius:5px;display:flex;align-items:center;justify-content:center;font-size:10px;flex-shrink:0;background:linear-gradient(135deg,var(--hi2),#3a3010);color:#fbbf24}
.overperm-chip-info{flex:1;min-width:0}
.overperm-chip-name{font-family:var(--mono);font-size:11px;font-weight:600;color:var(--txb);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.overperm-chip-type{font-size:9px;color:var(--tx2);text-transform:uppercase;letter-spacing:0.5px}
.overperm-collapse{margin-top:16px}
.overperm-toggle{font-family:var(--mono);font-size:10px;padding:8px 14px;background:var(--bg3);border:1px solid var(--bd);color:var(--tx2);border-radius:var(--radius-sm);cursor:pointer;transition:all 0.15s}
.overperm-toggle:hover{background:var(--olive-dark);border-color:var(--olive);color:#fff}

/* Path Blocks - Attack Chain Visualization */
.path-block{background:linear-gradient(145deg,var(--bg4),var(--bg3));border-radius:var(--radius);padding:20px;margin-top:16px;border:1px solid var(--bd);transition:all 0.2s}
.path-block:hover{border-color:var(--olive-dark)}
.path-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:10px}
.path-score{font-family:var(--mono);font-size:11px;color:var(--olive);background:var(--ok2);padding:4px 10px;border-radius:var(--radius-sm)}
.path-hops{display:flex;flex-direction:column;gap:6px}
.path-hop{display:flex;align-items:center;gap:14px;font-family:var(--mono);font-size:12px;padding:12px 16px;background:linear-gradient(135deg,var(--bg2),var(--bg3));border-radius:var(--radius-sm);border:1px solid var(--bd);transition:all 0.15s}
.path-hop:hover{border-color:var(--olive-dark);background:var(--bg3)}
.path-arrow{color:var(--olive);font-size:18px;font-weight:bold}

/* Tables */
.trust-table{width:100%;border-collapse:collapse;font-size:13px}
.trust-table th{text-align:left;padding:10px 14px;background:var(--bg3);font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:var(--tx2);font-family:var(--mono);font-weight:600}
.trust-table td{padding:10px 14px;border-bottom:1px solid var(--bd)}
.trust-table tr:hover td{background:var(--bg3)}

/* Escalation Table */
.escalation-table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:8px}
.escalation-table th{text-align:left;padding:8px 10px;background:var(--bg3);font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:var(--tx2);font-family:var(--mono);font-weight:600;border-bottom:2px solid var(--bd)}
.escalation-table td{padding:8px 10px;border-bottom:1px solid var(--bd);vertical-align:middle}
.escalation-table tr:hover td{background:var(--bg3)}
.escalation-table code{background:var(--bg4);padding:2px 6px;border-radius:4px;font-family:var(--mono)}

/* Remediation */
.remediation-box{background:var(--ok2);border-radius:var(--radius);padding:16px;margin-top:12px;border:1px solid var(--ok3)}
.remediation-box h5{font-size:11px;color:var(--ok);margin-bottom:8px;font-family:var(--mono);font-weight:600}
.remediation-box p{font-size:13px;color:var(--tx)}

/* Capability List */
.cap-list{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:6px}
.cap-list li{font-size:12px;color:var(--tx);padding:10px 14px;background:var(--bg3);border-radius:6px;display:flex;gap:10px;align-items:flex-start}
.cap-list li::before{content:"→";color:var(--ac);font-family:var(--mono);font-weight:600}

/* Copy Button - Dark Olive */
.copy-btn{font-family:var(--mono);font-size:10px;padding:6px 12px;background:var(--bg3);border:1px solid var(--olive-dark);color:var(--olive);border-radius:var(--radius);cursor:pointer;transition:all 0.15s;font-weight:500}
.copy-btn:hover{background:var(--olive-dark);border-color:var(--olive);color:#fff}
.copy-btn.copied{background:var(--olive);border-color:var(--olive);color:#000}

/* Footer */
.footer{text-align:center;padding:20px;font-size:11px;color:var(--tx2);border-top:1px solid var(--bd);font-family:var(--mono)}

.no-findings{text-align:center;padding:40px;color:var(--ok);font-family:var(--mono);font-size:14px;background:var(--ok2);border-radius:var(--radius)}

@media print{.copy-btn,.sidebar{display:none}.main-wrapper{margin-left:0}}

/* Graph Visualizer - Olive/Black Theme */
.graph-section{background:linear-gradient(145deg,var(--bg2),var(--bg3));border-radius:var(--radius-lg);margin:32px 0;overflow:hidden;border:1px solid var(--bd);box-shadow:var(--shadow-lg)}
.graph-header{background:linear-gradient(135deg,var(--olive-dark),#3a5a4a);padding:18px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:14px}
.graph-title{color:#fff;font-size:16px;font-weight:700;display:flex;align-items:center;gap:12px}
.graph-title-icon{width:32px;height:32px;background:linear-gradient(135deg,var(--olive),var(--olive-dark));border-radius:var(--radius-sm);display:flex;align-items:center;justify-content:center;box-shadow:0 0 10px rgba(132,169,140,0.3)}
.graph-controls{display:flex;gap:8px;flex-wrap:wrap}
.graph-btn{font-family:var(--mono);font-size:10px;padding:8px 14px;background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.2);color:#e2e8f0;border-radius:var(--radius-sm);cursor:pointer;transition:all 0.2s;font-weight:600}
.graph-btn:hover{background:rgba(132,169,140,0.3);border-color:var(--olive);color:#fff}
.graph-btn.active{background:var(--olive);border-color:var(--olive);color:#000}
.graph-btn.owned-active{background:var(--olive-bright);border-color:var(--olive-bright);color:#000}
.layout-btn.active{background:var(--olive);border-color:var(--olive);color:#000}
.graph-canvas{height:650px;background:linear-gradient(135deg,#0a0f0a 0%,#141a14 50%,#0d120d 100%);position:relative}
.graph-loading{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:var(--olive-dark);font-family:var(--mono);font-size:14px}
.graph-legend{background:var(--bg4);padding:14px 24px;display:flex;flex-wrap:wrap;gap:20px;border-top:1px solid var(--bd)}
.legend-item{display:flex;align-items:center;gap:8px;color:var(--tx);font-size:11px;font-family:var(--mono)}
.legend-dot{width:12px;height:12px;border-radius:50%;border:2px solid rgba(255,255,255,0.2)}
.legend-dot.admin{background:var(--cr);box-shadow:0 0 8px rgba(255,107,107,0.4)}
.legend-dot.shadow{background:var(--hi);box-shadow:0 0 8px rgba(251,191,36,0.4)}
.legend-dot.user{background:var(--olive);box-shadow:0 0 8px rgba(132,169,140,0.4)}
.legend-dot.role{background:var(--md);box-shadow:0 0 8px rgba(96,165,250,0.4)}
.legend-dot.group{background:var(--purple);box-shadow:0 0 8px rgba(167,139,250,0.4)}
.legend-dot.owned{background:var(--olive-bright);box-shadow:0 0 10px var(--olive-bright)}
.graph-info{position:absolute;bottom:20px;left:20px;background:rgba(10,15,10,0.95);border:1px solid var(--olive-dark);border-radius:var(--radius);padding:18px;min-width:300px;max-width:400px;display:none;color:#fff;font-size:12px;z-index:10;backdrop-filter:blur(12px)}
.graph-info.visible{display:block;animation:fade-in 0.2s ease}
.graph-info-title{font-weight:700;font-size:14px;margin-bottom:12px;color:var(--olive-bright)}
.graph-info-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(132,169,140,0.2)}
.graph-info-row:last-child{border-bottom:none}
.graph-info-key{color:var(--tx2)}
.graph-info-val{color:#fff;font-family:var(--mono)}
.graph-info-actions{margin-top:12px;padding-top:12px;border-top:1px solid var(--olive-dark);display:flex;gap:8px}
.graph-info-btn{font-family:var(--mono);font-size:10px;padding:8px 14px;background:var(--bg3);border:1px solid var(--olive-dark);color:var(--olive-light);border-radius:var(--radius-sm);cursor:pointer;transition:all 0.2s;flex:1;text-align:center;font-weight:600}
.graph-info-btn:hover{background:var(--olive-dark);color:#fff}
.graph-info-btn.owned{background:var(--olive);border-color:var(--olive);color:#000}
.graph-search{position:absolute;top:20px;left:20px;z-index:10}
.graph-search input{font-family:var(--mono);font-size:12px;padding:10px 14px;background:rgba(10,15,10,0.9);border:1px solid var(--olive-dark);color:#fff;border-radius:var(--radius-sm);width:240px;transition:all 0.2s}
.graph-search input:focus{outline:none;border-color:var(--olive);box-shadow:0 0 10px rgba(132,169,140,0.2)}
.graph-search input::placeholder{color:var(--tx2)}
.graph-toolbar{position:absolute;top:20px;right:20px;z-index:10;display:flex;flex-direction:column;gap:6px}
.graph-zoom-btn{width:36px;height:36px;background:rgba(10,15,10,0.9);border:1px solid var(--olive-dark);color:var(--olive-light);border-radius:var(--radius-sm);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:16px;transition:all 0.2s;font-weight:bold}
.graph-zoom-btn:hover{background:var(--olive-dark);color:#fff}
.graph-stats{position:absolute;top:20px;right:70px;background:rgba(10,15,10,0.9);border:1px solid var(--olive-dark);border-radius:var(--radius-sm);padding:10px 14px;color:var(--olive-light);font-size:10px;font-family:var(--mono);z-index:10}
.owned-panel{position:absolute;bottom:20px;right:20px;background:rgba(10,15,10,0.95);border:1px solid var(--olive);border-radius:var(--radius);padding:16px;min-width:200px;color:#fff;font-size:12px;z-index:10;backdrop-filter:blur(12px);display:none}
.owned-panel.visible{display:block;animation:fade-in 0.2s ease}
.owned-panel-title{font-weight:700;font-size:13px;color:var(--olive-bright);margin-bottom:10px;display:flex;align-items:center;gap:8px}
.owned-panel-list{max-height:160px;overflow-y:auto}
.owned-panel-item{padding:6px 10px;background:var(--bg3);border-radius:var(--radius-sm);margin-bottom:4px;display:flex;justify-content:space-between;align-items:center;font-family:var(--mono);font-size:10px;border:1px solid var(--bd)}
.owned-panel-clear{margin-top:10px;width:100%;padding:8px;background:var(--bg3);border:1px solid var(--cr3);color:var(--cr);border-radius:var(--radius-sm);cursor:pointer;font-family:var(--mono);font-size:10px;transition:all 0.2s;font-weight:600}
.owned-panel-clear:hover{background:var(--cr);border-color:var(--cr);color:#fff}
.faded{opacity:0.08!important}
.path-details-panel{position:absolute;top:70px;left:20px;background:rgba(10,15,10,0.98);border:1px solid var(--cr);border-radius:var(--radius);padding:20px;min-width:320px;max-width:400px;max-height:calc(100% - 110px);overflow-y:auto;color:#fff;font-size:12px;z-index:20;backdrop-filter:blur(12px);display:none}
.path-details-panel.visible{display:block;animation:fade-in 0.2s ease}
.path-details-title{font-weight:700;font-size:14px;color:var(--cr);margin-bottom:16px;display:flex;align-items:center;justify-content:space-between}
.path-details-close{cursor:pointer;font-size:18px;color:var(--tx2);transition:color 0.2s;width:24px;height:24px;display:flex;align-items:center;justify-content:center;border-radius:50%;background:var(--bg3)}
.path-details-close:hover{color:var(--cr);background:var(--cr2)}
.path-details-count{font-size:10px;color:var(--tx2);margin-bottom:12px;font-family:var(--mono)}
.path-item{background:var(--bg3);border:1px solid var(--bd);border-radius:var(--radius-sm);padding:14px;margin-bottom:10px;transition:all 0.2s}
.path-item:hover{border-color:var(--olive-dark)}
.path-item-header{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.path-item-num{width:24px;height:24px;background:linear-gradient(135deg,var(--cr),#ff4757);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0}
.path-item-source{color:#fff;font-family:var(--mono);font-size:11px;font-weight:600}
.path-item-arrow{text-align:center;color:var(--olive);font-size:18px;margin:4px 0}
.path-item-target{color:var(--olive-bright);font-family:var(--mono);font-size:11px;font-weight:600;margin-bottom:8px}
.path-item-action{background:var(--bg4);border-radius:var(--radius-sm);padding:10px 12px;font-size:10px;color:var(--hi);font-family:var(--mono);line-height:1.6;border:1px solid var(--bd)}
.path-item-action strong{color:#fff}
.path-item-badge{display:inline-block;font-size:8px;padding:3px 8px;border-radius:10px;text-transform:uppercase;font-weight:700;margin-left:8px}
.path-item-badge.admin{background:linear-gradient(135deg,var(--cr),#ff4757);color:#fff}
.path-item-badge.shadow{background:linear-gradient(135deg,var(--hi),#f59e0b);color:#000}

/* MITRE & Narrative */
.mitre-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.mitre-tag{font-family:var(--mono);font-size:10px;padding:4px 10px;background:var(--purple2);border:1px solid var(--purple3);color:var(--purple);border-radius:4px}
.attack-narrative{background:var(--cr2);border:1px solid var(--cr3);border-radius:var(--radius);padding:14px;margin-top:12px;font-size:13px;line-height:1.7;color:var(--tx)}
.attack-narrative strong{color:var(--cr)}

/* Account Section */
.account-section{margin-bottom:16px}
.account-header{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;background:var(--bg2);border:1px solid var(--bd);border-radius:var(--radius);cursor:pointer;transition:all 0.15s}
.account-header:hover{background:var(--bg3)}
.account-header-left{display:flex;align-items:center;gap:12px}
.account-chevron{font-size:10px;color:var(--tx2);transition:transform 0.2s}
.account-chevron.open{transform:rotate(90deg)}
.account-name{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--txb)}
.account-meta{font-size:11px;color:var(--tx2);font-family:var(--mono)}
.account-body{display:none;padding:14px 0}
.account-body.open{display:block}

/* Query Results - Modern Card Style with Explanations */
.query-card{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius-lg);padding:24px;margin-bottom:20px;transition:all 0.25s ease;position:relative;overflow:hidden}
.query-card::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%;background:linear-gradient(180deg,var(--olive),var(--olive-dark))}
.query-card:hover{box-shadow:var(--shadow-lg),var(--shadow-glow);border-color:var(--olive-dark);transform:translateY(-2px)}
.query-card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.query-card-title{font-size:16px;font-weight:700;color:var(--olive-light)}
.query-card-count{font-family:var(--mono);font-size:28px;font-weight:800;color:var(--olive-bright);text-shadow:0 0 20px rgba(132,169,140,0.3)}
.query-card-desc{font-size:13px;color:var(--tx);margin-bottom:16px;padding:14px;background:var(--bg4);border-radius:var(--radius-sm);border-left:3px solid var(--olive-dark);line-height:1.6}
.query-card-why{font-size:12px;color:var(--tx2);margin-bottom:16px;padding:12px 16px;background:linear-gradient(90deg,var(--hi2),transparent);border-radius:var(--radius-sm);border-left:3px solid var(--hi)}
.query-card-why strong{color:var(--hi)}
.query-card-body{display:flex;flex-direction:column;gap:12px}
.query-group{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px;background:var(--bg4);border-radius:var(--radius-sm)}
.query-group-label{font-family:var(--mono);font-size:9px;text-transform:uppercase;color:var(--olive);margin-right:8px;font-weight:700;letter-spacing:1.2px;min-width:60px}
.query-principal{font-family:var(--mono);font-size:10px;padding:6px 12px;background:var(--bg3);border-radius:var(--radius-sm);color:var(--tx);transition:all 0.2s ease;cursor:pointer;display:inline-flex;align-items:center;gap:5px;border:1px solid var(--bd)}
.query-principal:hover{background:var(--olive-dark);color:#fff;border-color:var(--olive);transform:translateY(-1px)}
.query-principal.user{background:linear-gradient(135deg,var(--ok2),#1a3a2a);color:var(--olive-bright);border-color:var(--olive-dark)}
.query-principal.role{background:linear-gradient(135deg,var(--md2),#1a2a4a);color:#60a5fa;border-color:#2a3a5a}
.query-principal.more{color:var(--tx2);font-style:italic;border-style:dashed;background:transparent}
.query-admin-tag{font-size:8px;padding:3px 6px;background:linear-gradient(135deg,#ff6b6b,#ff4757);color:#fff;border-radius:4px;margin-left:5px;font-weight:700;text-shadow:0 1px 2px rgba(0,0,0,0.3)}
.query-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.query-mini-card{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius);padding:18px;transition:all 0.25s ease}
.query-mini-card:hover{box-shadow:var(--shadow);border-color:var(--olive-dark);transform:translateY(-2px)}
.query-mini-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.query-action{font-size:9px;background:var(--bg4);color:var(--olive);padding:4px 10px;border-radius:var(--radius-sm);border:1px solid var(--olive-dark);font-weight:600}
.query-mini-title{font-size:13px;font-weight:700;color:var(--txb);margin-bottom:6px}
.query-mini-samples{font-size:10px;color:var(--tx2);font-family:var(--mono);line-height:1.5}

/* Principal Filters & Export */
.principal-controls{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:20px;align-items:center;justify-content:space-between;padding:14px 16px;background:var(--bg3);border-radius:var(--radius);border:1px solid var(--bd)}
.filter-group{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.filter-label{font-size:10px;color:var(--tx2);text-transform:uppercase;letter-spacing:0.5px;margin-right:6px}
.filter-btn{font-family:var(--mono);font-size:10px;padding:6px 12px;background:var(--bg4);border:1px solid var(--bd);color:var(--tx2);border-radius:20px;cursor:pointer;transition:all 0.15s}
.filter-btn:hover{border-color:var(--olive);color:var(--olive)}
.filter-btn.active{background:var(--olive);border-color:var(--olive);color:#000;font-weight:600}
.filter-btn.critical{border-color:var(--cr3)}
.filter-btn.critical:hover,.filter-btn.critical.active{background:var(--cr);border-color:var(--cr);color:#fff}
.filter-btn.high{border-color:var(--hi3)}
.filter-btn.high:hover,.filter-btn.high.active{background:var(--hi);border-color:var(--hi);color:#000}
.export-group{display:flex;gap:6px}
.export-btn{font-family:var(--mono);font-size:10px;padding:6px 12px;background:transparent;border:1px solid var(--olive-dark);color:var(--olive);border-radius:var(--radius-sm);cursor:pointer;transition:all 0.15s;display:flex;align-items:center;gap:4px}
.export-btn:hover{background:var(--olive-dark);color:#fff;border-color:var(--olive)}
.export-btn svg{width:12px;height:12px}
.query-card[data-hidden="true"]{display:none}
.query-mini-card[data-hidden="true"]{display:none}

/* Syntax Highlighting - Sublime/Monokai Style */
.cli-block{position:relative;margin:16px 0;border-radius:var(--radius);overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,0.4)}
.cli-block-header{display:flex;justify-content:flex-end;align-items:center;padding:8px 16px;background:#272822;border-bottom:1px solid #3e3d32}
.cli-code{font-family:'SF Mono','Fira Code','Monaco','Consolas',var(--mono);font-size:12px;background:#272822;color:#f8f8f2;padding:16px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;line-height:1.6;tab-size:4;-moz-tab-size:4;max-width:100%}
.cli-code .ln{color:#75715e;user-select:none;margin-right:16px;min-width:24px;display:inline-block;text-align:right}
.cli-code .comment{color:#75715e;font-style:italic}
.cli-code .cmd{color:#a6e22e;font-weight:600}
.cli-code .subcmd{color:#66d9ef;font-weight:500}
.cli-code .flag{color:#fd971f}
.cli-code .flagval{color:#e6db74}
.cli-code .str{color:#e6db74}
.cli-code .var{color:#ae81ff}
.cli-code .arn{color:#66d9ef;text-decoration:underline;text-decoration-style:dotted;text-underline-offset:2px}
.cli-code .pipe{color:#f92672;font-weight:bold}
.cli-code .redir{color:#f92672}
.cli-code .builtin{color:#66d9ef;font-style:italic}
.cli-code .num{color:#ae81ff}
.cli-code .path{color:#fd971f}

/* Copy ARN & Toast - Dark Olive */
.copy-arn{display:inline-flex;align-items:center;gap:3px;cursor:pointer;padding:2px 4px;border-radius:3px;transition:all 0.15s;font-size:10px}
.copy-arn:hover{background:var(--ok2);color:var(--olive)}
.copy-arn .copy-icon{opacity:0;transition:opacity 0.15s}
.copy-arn:hover .copy-icon{opacity:1}
.copied-toast{position:fixed;bottom:24px;right:24px;background:var(--olive);color:#000;padding:12px 18px;border-radius:var(--radius);font-family:var(--mono);font-size:12px;z-index:9999;animation:slide-up 0.2s ease;box-shadow:var(--shadow-lg);font-weight:500}
.arn-text{cursor:pointer;transition:all 0.15s;padding:2px 4px;border-radius:3px}
.arn-text:hover{background:var(--ok2);color:var(--olive)}

/* Export Panel - Dark Olive */
.export-panel{position:fixed;bottom:20px;left:260px;right:20px;background:var(--bg2);border:1px solid var(--olive-dark);border-radius:var(--radius);padding:14px 18px;display:none;z-index:1000;box-shadow:var(--shadow-lg)}
.export-panel.visible{display:flex;align-items:center;justify-content:space-between;animation:slide-up 0.2s ease}
.export-panel-info{color:var(--tx);font-size:12px}
.export-panel-count{color:var(--olive);font-family:var(--mono);font-weight:600;margin-left:6px}
.export-panel-actions{display:flex;gap:8px}
.export-btn{font-family:var(--mono);font-size:10px;padding:8px 14px;background:var(--bg3);border:1px solid var(--olive-dark);color:var(--olive);border-radius:var(--radius);cursor:pointer;transition:all 0.15s}
.export-btn:hover{background:var(--olive-dark);border-color:var(--olive);color:#fff}
.export-btn.primary{background:var(--olive);border-color:var(--olive);color:#000;font-weight:500}
.export-btn.primary:hover{background:var(--olive-light)}

/* Run Info Panel */
.run-info{background:linear-gradient(145deg,var(--bg2),var(--bg3));border:1px solid var(--bd);border-radius:var(--radius-lg);padding:20px 24px;margin-bottom:24px}
.run-info-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--bd)}
.run-info-title{font-size:14px;font-weight:700;color:var(--txb);display:flex;align-items:center;gap:10px}
.run-info-title::before{content:"";width:4px;height:16px;background:var(--olive);border-radius:2px}
.run-info-badge{font-family:var(--mono);font-size:10px;padding:4px 10px;background:var(--olive-dark);color:var(--olive-bright);border-radius:var(--radius-sm)}
.run-info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
.run-info-item{display:flex;flex-direction:column;gap:4px}
.run-info-label{font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:var(--tx2);font-weight:600}
.run-info-value{font-family:var(--mono);font-size:12px;color:var(--tx);word-break:break-word}
.run-info-value.highlight{color:var(--olive-bright)}
.run-info-regions{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
.run-info-region{font-family:var(--mono);font-size:10px;padding:3px 8px;background:var(--bg4);border:1px solid var(--bd);border-radius:4px;color:var(--tx2)}
.run-info-region.excluded{background:var(--cr2);border-color:var(--cr3);color:var(--cr)}
.run-info-toggle{font-family:var(--mono);font-size:10px;color:var(--olive);cursor:pointer;margin-left:8px}
.run-info-toggle:hover{text-decoration:underline}

/* Site Footer */
.site-footer{background:rgba(10,10,10,0.95);border-top:1px solid var(--bd);padding:12px 24px;display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--tx2)}
.site-footer a{color:var(--olive);text-decoration:none}
.site-footer a:hover{text-decoration:underline}

/* Policy Viewer */
.policy-viewer{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.85);z-index:1000;display:none;overflow:auto;padding:40px}
.policy-viewer.visible{display:flex;justify-content:center;align-items:flex-start}
.policy-viewer-content{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--radius);width:min(90%,900px);max-height:calc(100vh - 80px);overflow:hidden;display:flex;flex-direction:column}
.policy-viewer-header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid var(--bd);background:var(--bg3)}
.policy-viewer-title{font-weight:600;font-size:14px;color:var(--tx);display:flex;align-items:center;gap:10px}
.policy-viewer-arn{font-family:var(--mono);font-size:11px;color:var(--tx2);max-width:500px;overflow:hidden;text-overflow:ellipsis}
.policy-viewer-close{background:none;border:none;color:var(--tx2);font-size:24px;cursor:pointer;padding:4px 8px;line-height:1}
.policy-viewer-close:hover{color:var(--cr)}
.policy-viewer-body{flex:1;overflow:auto;padding:0}
.policy-code{margin:0;padding:16px;font-family:var(--mono);font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-word;background:var(--bg)}
.policy-code .key{color:var(--olive)}
.policy-code .string{color:#7dd3fc}
.policy-code .boolean{color:#f472b6}
.policy-code .null{color:var(--tx2)}
.policy-code .number{color:#a78bfa}
.policy-code .issue{background:rgba(239,68,68,0.2);display:inline;padding:2px 0;border-radius:2px}
.policy-code .issue-line{background:rgba(239,68,68,0.15);display:block;margin:0 -16px;padding:0 16px;border-left:3px solid var(--cr)}
.policy-viewer-footer{padding:12px 20px;border-top:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center;background:var(--bg3)}
.policy-viewer-legend{display:flex;gap:16px;font-size:11px;color:var(--tx2)}
.policy-viewer-legend span{display:flex;align-items:center;gap:4px}
.policy-viewer-legend .issue-dot{width:10px;height:10px;background:rgba(239,68,68,0.4);border:1px solid var(--cr);border-radius:2px}
.view-policy-btn{background:var(--bg3);border:1px solid var(--bd);color:var(--tx);font-size:10px;padding:4px 10px;border-radius:4px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;font-family:var(--mono)}
.view-policy-btn:hover{background:var(--bg4);border-color:var(--olive)}
.aws-policy-badge{background:var(--md2);border:1px solid #60a5fa33;color:#60a5fa;font-size:9px;padding:3px 8px;border-radius:4px;display:inline-flex;align-items:center;gap:3px;font-family:var(--mono);cursor:default}

/* Pagination */
.pagination{display:flex;align-items:center;justify-content:center;gap:6px;margin-top:16px;padding:12px;background:var(--bg3);border-radius:var(--radius);border:1px solid var(--bd)}
.pagination-btn{font-family:var(--mono);font-size:11px;padding:6px 12px;background:var(--bg4);border:1px solid var(--bd);color:var(--tx);border-radius:4px;cursor:pointer;transition:all 0.15s}
.pagination-btn:hover:not(:disabled){background:var(--olive-dark);border-color:var(--olive);color:var(--olive-bright)}
.pagination-btn:disabled{opacity:0.4;cursor:not-allowed}
.pagination-btn.active{background:var(--olive);border-color:var(--olive);color:#000;font-weight:600}
.pagination-info{font-size:11px;color:var(--tx2);font-family:var(--mono);padding:0 12px}
.pagination-jump{display:flex;align-items:center;gap:6px;margin-left:12px}
.pagination-jump input{width:50px;padding:4px 8px;font-size:11px;font-family:var(--mono);background:var(--bg);border:1px solid var(--bd);border-radius:4px;color:var(--tx);text-align:center}
.pagination-jump input:focus{outline:none;border-color:var(--olive)}
"""

GRAPH_JS = """
// ═══════════════════ Graph Visualizer with Owned Nodes ═══════════════════
let cy = null;
let graphData = null;
let ownedNodes = new Set();
let selectedNodeId = null;

function initGraph(data) {
    graphData = data;
    if (!data.nodes || data.nodes.length === 0) {
        document.querySelector('.graph-loading').textContent = 'No privilege escalation paths found';
        return;
    }

    cy = cytoscape({
        container: document.getElementById('cy'),
        elements: data,
        style: [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'font-size': '11px',
                    'color': '#94a3b8',
                    'text-margin-y': 8,
                    'text-wrap': 'ellipsis',
                    'text-max-width': '100px',
                    'width': 44,
                    'height': 44,
                    'background-color': 'data(color)',
                    'border-width': 3,
                    'border-color': '#334155'
                }
            },
            {
                selector: 'node[type="admin"]',
                style: {
                    'background-color': '#ef4444',
                    'border-color': '#fca5a5',
                    'shape': 'star',
                    'width': 56,
                    'height': 56
                }
            },
            {
                selector: 'node[type="shadow"]',
                style: {
                    'background-color': '#f59e0b',
                    'border-color': '#fcd34d'
                }
            },
            {
                selector: 'node[type="user"]',
                style: {
                    'background-color': '#84a98c',
                    'border-color': '#a4c3ac',
                    'shape': 'ellipse'
                }
            },
            {
                selector: 'node[type="role"]',
                style: {
                    'background-color': '#52796f',
                    'border-color': '#84a98c',
                    'shape': 'round-rectangle'
                }
            },
            {
                selector: 'node[type="group"]',
                style: {
                    'background-color': '#8b5cf6',
                    'border-color': '#c4b5fd',
                    'shape': 'diamond'
                }
            },
            {
                selector: 'node.owned',
                style: {
                    'background-color': '#a4c3ac',
                    'border-color': '#cad2c5',
                    'border-width': 4,
                    'overlay-color': '#84a98c',
                    'overlay-opacity': 0.25,
                    'overlay-padding': 10
                }
            },
            {
                selector: 'node:selected',
                style: {
                    'border-width': 4,
                    'border-color': '#cad2c5',
                    'overlay-opacity': 0.3,
                    'overlay-color': '#84a98c'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#3a4a3a',
                    'target-arrow-color': '#3a4a3a',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'arrow-scale': 1.3
                }
            },
            {
                selector: 'edge[severity="critical"]',
                style: {
                    'line-color': '#ef4444',
                    'target-arrow-color': '#ef4444',
                    'width': 3
                }
            },
            {
                selector: 'edge[severity="high"]',
                style: {
                    'line-color': '#f59e0b',
                    'target-arrow-color': '#f59e0b'
                }
            },
            {
                selector: 'edge.attack-path',
                style: {
                    'line-color': '#84a98c',
                    'target-arrow-color': '#84a98c',
                    'width': 4,
                    'line-style': 'solid'
                }
            },
            {
                selector: 'node.attack-path',
                style: {
                    'border-color': '#a4c3ac',
                    'border-width': 5
                }
            },
            {
                selector: 'edge:selected',
                style: {
                    'line-color': '#cad2c5',
                    'target-arrow-color': '#cad2c5',
                    'width': 4
                }
            }
        ],
        layout: {
            name: 'cose',
            animate: true,
            animationDuration: 500,
            nodeRepulsion: function(node){ return 10000; },
            idealEdgeLength: function(edge){ return 120; },
            nodeOverlap: 30,
            padding: 60
        },
        minZoom: 0.2,
        maxZoom: 3,
        wheelSensitivity: 0.3
    });

    // Node click handler
    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        selectedNodeId = node.id();
        showNodeInfo(node.data(), node.id());
    });

    // Edge click handler
    cy.on('tap', 'edge', function(evt) {
        const edge = evt.target;
        showEdgeInfo(edge.data());
    });

    // Background click
    cy.on('tap', function(evt) {
        if (evt.target === cy) {
            document.querySelector('.graph-info').classList.remove('visible');
            selectedNodeId = null;
        }
    });

    // Update stats
    document.querySelector('.graph-stats').textContent =
        data.nodes.length + ' nodes | ' + data.edges.length + ' edges';
    document.querySelector('.graph-loading').style.display = 'none';
}

function showNodeInfo(data, nodeId) {
    const info = document.querySelector('.graph-info');
    const isOwned = ownedNodes.has(nodeId);
    const isAdmin = data.type === 'admin' || data.is_admin;

    info.innerHTML = `
        <div class="graph-info-title">${escapeHtml(data.label)}</div>
        <div class="graph-info-row"><span class="graph-info-key">Type:</span><span class="graph-info-val">${data.type}</span></div>
        <div class="graph-info-row"><span class="graph-info-key">ARN:</span><span class="graph-info-val" style="font-size:10px">${escapeHtml(data.arn || 'N/A')}</span></div>
        ${isAdmin ? '<div class="graph-info-row"><span class="graph-info-key">Admin:</span><span class="graph-info-val" style="color:#ef4444">Yes</span></div>' : ''}
        ${isOwned ? '<div class="graph-info-row"><span class="graph-info-key">Status:</span><span class="graph-info-val" style="color:#22c55e">OWNED</span></div>' : ''}
        ${data.paths_to_admin ? '<div class="graph-info-row"><span class="graph-info-key">Paths to Admin:</span><span class="graph-info-val">' + data.paths_to_admin + '</span></div>' : ''}
        <div class="graph-info-actions">
            <button class="graph-info-btn ${isOwned ? 'owned' : ''}" onclick="toggleOwned('${escapeJsString(nodeId)}')">${isOwned ? '✓ Owned' : 'Mark Owned'}</button>
            ${!isAdmin ? '<button class="graph-info-btn" onclick="showPathsToAdmin(\\''+escapeJsString(nodeId)+'\\')">Paths to Admin</button>' : ''}
        </div>
    `;
    info.classList.add('visible');
}

function showEdgeInfo(data) {
    const info = document.querySelector('.graph-info');
    info.innerHTML = `
        <div class="graph-info-title">Escalation Path</div>
        <div class="graph-info-row"><span class="graph-info-key">From:</span><span class="graph-info-val">${escapeHtml(data.source_name || data.source)}</span></div>
        <div class="graph-info-row"><span class="graph-info-key">To:</span><span class="graph-info-val">${escapeHtml(data.target_name || data.target)}</span></div>
        <div class="graph-info-row"><span class="graph-info-key">Technique:</span><span class="graph-info-val">${escapeHtml(data.reason || 'Unknown')}</span></div>
        <div class="graph-info-row"><span class="graph-info-key">Severity:</span><span class="graph-info-val" style="color:${data.severity === 'critical' ? '#ef4444' : '#f59e0b'}">${data.severity || 'medium'}</span></div>
    `;
    info.classList.add('visible');
}

function toggleOwned(nodeId) {
    if (!cy) return;
    const node = cy.getElementById(nodeId);
    if (!node.length) return;

    if (ownedNodes.has(nodeId)) {
        ownedNodes.delete(nodeId);
        node.removeClass('owned');
    } else {
        ownedNodes.add(nodeId);
        node.addClass('owned');
    }

    updateOwnedPanel();
    if (selectedNodeId === nodeId) {
        showNodeInfo(node.data(), nodeId);
    }

    // Update button state
    const btn = document.querySelector('[data-type="owned"]');
    if (btn) {
        btn.classList.toggle('owned-active', ownedNodes.size > 0);
    }
}

function updateOwnedPanel() {
    const panel = document.querySelector('.owned-panel');
    const list = panel.querySelector('.owned-panel-list');

    if (ownedNodes.size === 0) {
        panel.classList.remove('visible');
        return;
    }

    panel.classList.add('visible');
    list.innerHTML = '';

    ownedNodes.forEach(nodeId => {
        const node = cy.getElementById(nodeId);
        if (node.length) {
            const item = document.createElement('div');
            item.className = 'owned-panel-item';
            item.innerHTML = `
                <span>${escapeHtml(node.data('label'))}</span>
                <span style="cursor:pointer;color:#ef4444" onclick="toggleOwned('${escapeJsString(nodeId)}')">×</span>
            `;
            list.appendChild(item);
        }
    });
}

function clearOwned() {
    ownedNodes.forEach(nodeId => {
        const node = cy.getElementById(nodeId);
        if (node.length) node.removeClass('owned');
    });
    ownedNodes.clear();
    updateOwnedPanel();
    cy.elements().removeClass('attack-path');
    cy.elements().style('opacity', 1);

    const btn = document.querySelector('[data-type="owned"]');
    if (btn) btn.classList.remove('owned-active');
}

function showPathsToAdmin(startNodeId) {
    if (!cy) return;

    cy.elements().removeClass('attack-path');
    cy.elements().style('opacity', 0.15);

    const startNode = cy.getElementById(startNodeId);
    const adminNodes = cy.nodes('[type="admin"]');

    // BFS to find paths to admin
    let pathFound = false;
    adminNodes.forEach(admin => {
        const paths = cy.elements().dijkstra({
            root: startNode,
            directed: true
        });

        const path = paths.pathTo(admin);
        if (path.length > 0) {
            pathFound = true;
            path.addClass('attack-path');
            path.style('opacity', 1);
        }
    });

    if (!pathFound) {
        startNode.style('opacity', 1);
        alert('No direct path to admin found from this node');
    } else {
        startNode.addClass('attack-path');
        startNode.style('opacity', 1);
    }
}

function showOwnedPaths() {
    if (!cy || ownedNodes.size === 0) return;

    cy.elements().removeClass('attack-path');
    cy.elements().style('opacity', 0.15);

    const adminNodes = cy.nodes('[type="admin"]');

    ownedNodes.forEach(nodeId => {
        const startNode = cy.getElementById(nodeId);
        startNode.style('opacity', 1);
        startNode.addClass('attack-path');

        adminNodes.forEach(admin => {
            // Use BFS to find all paths
            const paths = cy.elements().dijkstra({
                root: startNode,
                directed: true
            });

            const path = paths.pathTo(admin);
            if (path.length > 0) {
                path.addClass('attack-path');
                path.style('opacity', 1);
            }
        });
    });

    adminNodes.style('opacity', 1);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

function escapeJsString(str) {
    // Escape characters that could break out of JS string literals
    return (str || '').replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'").replace(/"/g, '\\\\"');
}

function graphZoom(factor) {
    if (cy) cy.zoom(cy.zoom() * factor);
}

function graphFit() {
    if (cy) cy.fit(50);
}

function graphCenter() {
    if (cy) cy.center();
}

function graphSearch(query) {
    if (!cy || !query) {
        if (cy) {
            cy.elements().style('opacity', 1);
            cy.elements().removeClass('attack-path');
        }
        return;
    }
    query = query.toLowerCase();
    const matched = cy.nodes().filter(n =>
        (n.data('label') || '').toLowerCase().includes(query) ||
        (n.data('arn') || '').toLowerCase().includes(query)
    );
    cy.elements().style('opacity', 0.15);
    matched.style('opacity', 1);
    matched.connectedEdges().style('opacity', 1);
    matched.neighborhood().style('opacity', 0.8);

    if (matched.length > 0) {
        cy.animate({ fit: { eles: matched, padding: 100 }, duration: 300 });
    }
}

function graphLayout(name) {
    if (!cy) return;
    const layouts = {
        cose: { name: 'cose', animate: true, animationDuration: 500, nodeRepulsion: () => 10000, idealEdgeLength: () => 120 },
        circle: { name: 'circle', animate: true, animationDuration: 300, padding: 50 },
        breadthfirst: { name: 'breadthfirst', animate: true, animationDuration: 300, directed: true, padding: 50, spacingFactor: 1.5 },
        grid: { name: 'grid', animate: true, animationDuration: 300, padding: 50 },
        concentric: { name: 'concentric', animate: true, animationDuration: 300, concentric: n => n.data('is_admin') ? 10 : (ownedNodes.has(n.id()) ? 1 : 5), levelWidth: () => 2 }
    };
    cy.layout(layouts[name] || layouts.cose).run();

    document.querySelectorAll('.layout-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('.layout-btn[data-layout="'+name+'"]')?.classList.add('active');
}

function exportGraph(format) {
    if (!cy) return;

    if (format === 'png') {
        const png = cy.png({ output: 'blob', scale: 2, bg: '#0f172a' });
        const url = URL.createObjectURL(png);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'privmapper_graph_' + new Date().toISOString().slice(0,10) + '.png';
        a.click();
        URL.revokeObjectURL(url);
    } else if (format === 'svg') {
        const svg = cy.svg({ scale: 1, full: true, bg: '#0f172a' });
        const blob = new Blob([svg], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'privmapper_graph_' + new Date().toISOString().slice(0,10) + '.svg';
        a.click();
        URL.revokeObjectURL(url);
    }
}

function highlightPaths(type) {
    if (!cy) return;

    // Reset all elements
    cy.elements().style('opacity', 1).style('display', 'element');
    cy.elements().removeClass('attack-path');
    closePathDetails();

    if (type === 'all') {
        return;
    }

    if (type === 'owned') {
        if (ownedNodes.size > 0) {
            showOwnedPaths();
        }
        return;
    }

    let matchingEdges = [];
    let pathDetails = [];

    if (type === 'admins') {
        // Get all edges that lead to admins (directly or indirectly)
        const admins = cy.nodes('[type="admin"]');
        const adminIds = new Set();
        admins.forEach(a => adminIds.add(a.id()));

        // Find all paths to admin nodes
        cy.edges().forEach(edge => {
            const targetId = edge.data('target');
            const targetNode = cy.getElementById(targetId);
            if (targetNode.length && (targetNode.data('type') === 'admin' || targetNode.data('is_admin'))) {
                matchingEdges.push(edge);
                pathDetails.push({
                    source: edge.data('source_name') || edge.data('source').split('/').pop(),
                    target: edge.data('target_name') || edge.data('target').split('/').pop(),
                    reason: edge.data('reason') || edge.data('short_reason') || 'Unknown',
                    isAdmin: true
                });
            }
        });

        // Also include edges leading TO nodes that have edges to admin
        cy.edges().forEach(edge => {
            const targetId = edge.data('target');
            if (matchingEdges.some(e => e.data('source') === targetId)) {
                if (!matchingEdges.includes(edge)) {
                    matchingEdges.push(edge);
                    pathDetails.push({
                        source: edge.data('source_name') || edge.data('source').split('/').pop(),
                        target: edge.data('target_name') || edge.data('target').split('/').pop(),
                        reason: edge.data('reason') || edge.data('short_reason') || 'Unknown',
                        isAdmin: false
                    });
                }
            }
        });

    } else if (type === 'critical') {
        cy.edges('[severity="critical"]').forEach(edge => {
            matchingEdges.push(edge);
            pathDetails.push({
                source: edge.data('source_name') || edge.data('source').split('/').pop(),
                target: edge.data('target_name') || edge.data('target').split('/').pop(),
                reason: edge.data('reason') || edge.data('short_reason') || 'Unknown',
                severity: 'critical'
            });
        });
    }

    // Hide non-matching elements completely
    cy.elements().style('display', 'none');

    // Show only matching edges and their connected nodes
    matchingEdges.forEach(edge => {
        edge.style('display', 'element').style('opacity', 1);
        edge.addClass('attack-path');
        edge.connectedNodes().style('display', 'element').style('opacity', 1);
    });

    // Show path details panel
    if (pathDetails.length > 0) {
        showPathDetailsPanel(type, pathDetails);
    }
}

function showPathDetailsPanel(type, paths) {
    const panel = document.getElementById('path-details');
    const countEl = panel.querySelector('.path-details-count');
    const listEl = panel.querySelector('.path-details-list');
    const titleEl = panel.querySelector('.path-details-title span:first-child');

    titleEl.textContent = type === 'admins' ? 'Paths to Admin' : 'Critical Paths';
    countEl.textContent = paths.length + ' attack path' + (paths.length !== 1 ? 's' : '') + ' found';

    listEl.innerHTML = paths.map((p, i) => `
        <div class="path-item">
            <div class="path-item-header">
                <div class="path-item-num">${i + 1}</div>
                <div class="path-item-source">${escapeHtml(p.source)}</div>
                ${p.isAdmin ? '<span class="path-item-badge admin">→ ADMIN</span>' : ''}
                ${p.severity === 'critical' ? '<span class="path-item-badge admin">CRITICAL</span>' : ''}
            </div>
            <div class="path-item-arrow">↓</div>
            <div class="path-item-target">${escapeHtml(p.target)}</div>
            <div class="path-item-action">
                <strong>Action:</strong> ${escapeHtml(p.reason)}
            </div>
        </div>
    `).join('');

    panel.classList.add('visible');
}

function closePathDetails() {
    document.getElementById('path-details').classList.remove('visible');
}
"""

APP_JS = """
// ═══════════════════ Cyberpunk UI Functions ═══════════════════

function toggleAccount(id) {
    const body = document.getElementById('ab-' + id);
    const chev = document.getElementById('ac-' + id);
    body.classList.toggle('open');
    chev.classList.toggle('open');
}

function toggleFinding(id) {
    const body = document.getElementById('fb-' + id);
    const chev = document.getElementById('fc-' + id);
    body.classList.toggle('open');
    chev.classList.toggle('open');
}

function copyText(btn) {
    // Get text from data-copy attribute or from sibling cli-code element
    let text = btn.dataset.copy;
    if (!text) {
        const cliBlock = btn.closest('.cli-block');
        if (cliBlock) {
            const codeEl = cliBlock.querySelector('.cli-code');
            if (codeEl) text = codeEl.textContent;
        }
    }
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.classList.add('copied');
        btn.textContent = 'Copied!';
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.textContent = orig;
        }, 1500);
    }).catch(() => {
        // Fallback for older browsers
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    });
}

// ═══════════════════ Copy ARN with Toast ═══════════════════
function copyArn(btn, arn) {
    // Tolerate the single-argument call form copyArn('arn') used by query-result and
    // chip contexts (where there is no button element to update). Without this, those
    // callers passed the ARN as `btn`, leaving `arn` undefined and copying "undefined".
    if (arn === undefined && typeof btn === 'string') { arn = btn; btn = null; }
    navigator.clipboard.writeText(arn).then(() => {
        if (btn && btn.textContent !== undefined) {
            const orig = btn.textContent;
            btn.classList.add('copied');
            btn.textContent = 'Copied!';
            setTimeout(() => {
                btn.classList.remove('copied');
                btn.textContent = orig;
            }, 1200);
        }
        showToast('ARN copied: ' + String(arn).split('/').pop());
    });
}

// Toggle show more principals (card view)
function togglePrincipals(btn, fid) {
    const showing = btn.dataset.showing === 'true';
    const cards = document.querySelectorAll('.principal-card[data-principal-idx="' + fid + '"].principals-hidden');
    cards.forEach(card => {
        card.classList.toggle('show', !showing);
    });
    btn.dataset.showing = !showing ? 'true' : 'false';
    const count = cards.length;
    btn.textContent = showing ? 'Show ' + count + ' more principals' : 'Show less';
}

// Toggle show more principals (chip view for overly permissive)
function togglePrincipalsChips(btn, fid) {
    const showing = btn.dataset.showing === 'true';
    const chips = document.querySelectorAll('.overperm-chip[data-principal-idx="' + fid + '"].principals-hidden');
    chips.forEach(chip => {
        chip.classList.toggle('show', !showing);
    });
    btn.dataset.showing = !showing ? 'true' : 'false';
    const count = chips.length;
    btn.textContent = showing ? 'Show ' + count + ' more principals' : 'Show less';
}

function copyFinding(title, principals) {
    const text = '## ' + title + '\\n\\nAffected Principals:\\n' + principals.map(p => '- ' + p).join('\\n');
    navigator.clipboard.writeText(text).then(() => {
        showToast('Finding copied to clipboard');
    });
}

function copyAllArns(arns) {
    navigator.clipboard.writeText(arns.join('\\n')).then(() => {
        showToast(arns.length + ' ARNs copied to clipboard');
    });
}

function showToast(message) {
    // Remove existing toast
    const existing = document.querySelector('.copied-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'copied-toast';
    // Use textContent to prevent XSS, add checkmark as Unicode
    toast.textContent = '\u2713 ' + message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(20px)';
        setTimeout(() => toast.remove(), 300);
    }, 2000);
}

// ═══════════════════ Selection for Bulk Export ═══════════════════
let selectedArns = new Set();

function toggleArnSelection(arn, element) {
    if (selectedArns.has(arn)) {
        selectedArns.delete(arn);
        element.classList.remove('selected');
    } else {
        selectedArns.add(arn);
        element.classList.add('selected');
    }
    updateExportPanel();
}

function updateExportPanel() {
    const panel = document.getElementById('export-panel');
    const count = document.getElementById('export-count');
    if (selectedArns.size > 0) {
        panel.classList.add('visible');
        count.textContent = selectedArns.size;
    } else {
        panel.classList.remove('visible');
    }
}

function exportSelected(format) {
    const arns = Array.from(selectedArns);
    if (format === 'markdown') {
        const md = '## Selected Principals\\n\\n' + arns.map(a => '- `' + a + '`').join('\\n');
        navigator.clipboard.writeText(md).then(() => showToast('Exported as Markdown'));
    } else if (format === 'json') {
        navigator.clipboard.writeText(JSON.stringify(arns, null, 2)).then(() => showToast('Exported as JSON'));
    } else {
        navigator.clipboard.writeText(arns.join('\\n')).then(() => showToast('Exported as text'));
    }
}

function clearSelection() {
    selectedArns.clear();
    document.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
    updateExportPanel();
}

// ═══════════════════ Filter & Export for Principals ═══════════════════
function filterQueries(category, btn) {
    // Update active button
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    // Filter query cards
    const cards = document.querySelectorAll('.query-card');
    cards.forEach(card => {
        if (category === 'all') {
            card.dataset.hidden = 'false';
            card.style.display = '';
        } else {
            const cardCat = card.dataset.category || '';
            if (cardCat === category) {
                card.dataset.hidden = 'false';
                card.style.display = '';
            } else {
                card.dataset.hidden = 'true';
                card.style.display = 'none';
            }
        }
    });
}

function exportPrincipals(format) {
    // Collect all visible principals from query cards
    const principals = [];
    const visibleCards = document.querySelectorAll('.query-card:not([data-hidden="true"])');

    visibleCards.forEach(card => {
        const category = card.dataset.category || 'unknown';
        const title = card.querySelector('.query-card-title')?.textContent || '';
        const arnElements = card.querySelectorAll('[data-arn]');
        arnElements.forEach(el => {
            principals.push({
                category: category,
                title: title,
                arn: el.dataset.arn,
                name: el.textContent.replace(/ADMIN$/, '').trim(),
                isAdmin: el.textContent.includes('ADMIN')
            });
        });
    });

    if (principals.length === 0) {
        showToast('No principals to export');
        return;
    }

    let output = '';
    let filename = 'principals_export';
    let mimeType = 'text/plain';

    if (format === 'csv') {
        output = 'Category,Title,Name,ARN,IsAdmin\\n';
        principals.forEach(p => {
            output += `"${p.category}","${p.title}","${p.name}","${p.arn}",${p.isAdmin}\\n`;
        });
        filename += '.csv';
        mimeType = 'text/csv';
    } else if (format === 'json') {
        output = JSON.stringify(principals, null, 2);
        filename += '.json';
        mimeType = 'application/json';
    }

    // Create download
    const blob = new Blob([output], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast(`Exported ${principals.length} principals as ${format.toUpperCase()}`);
}

// ═══════════════════ Principals Table Filter ═══════════════════
function filterPrincipalsTable(filter) {
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`.filter-btn[data-filter="${filter}"]`)?.classList.add('active');

    document.querySelectorAll('.principals-table tbody tr').forEach(row => {
        let show = true;
        if (filter === 'admin') show = row.dataset.admin === 'true';
        else if (filter === 'shadow') show = row.dataset.shadow === 'true';
        else if (filter === 'dangerous') show = row.dataset.dangerous === 'true';
        row.style.display = show ? '' : 'none';
    });
}

function exportPrincipalsTable(format) {
    const rows = document.querySelectorAll('.principals-table tbody tr:not([style*="display: none"])');
    const data = [];
    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        data.push({
            name: cells[0]?.textContent?.trim() || '',
            type: cells[1]?.textContent?.trim() || '',
            isAdmin: row.dataset.admin === 'true',
            isShadowAdmin: row.dataset.shadow === 'true',
            hasDangerousActions: row.dataset.dangerous === 'true'
        });
    });

    if (data.length === 0) {
        showToast('No principals to export');
        return;
    }

    let output = '';
    let filename = 'principals';
    let mimeType = 'text/plain';

    if (format === 'csv') {
        output = 'Name,Type,IsAdmin,IsShadowAdmin,HasDangerousActions\\n';
        data.forEach(p => {
            output += `"${p.name}","${p.type}",${p.isAdmin},${p.isShadowAdmin},${p.hasDangerousActions}\\n`;
        });
        filename += '.csv';
        mimeType = 'text/csv';
    } else {
        output = JSON.stringify(data, null, 2);
        filename += '.json';
        mimeType = 'application/json';
    }

    const blob = new Blob([output], {type: mimeType});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(`Exported ${data.length} principals as ${format.toUpperCase()}`);
}

// ═══════════════════ Pagination ═══════════════════
const paginationState = {};

function initPagination(containerId, itemSelector, perPage = 10) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const items = container.querySelectorAll(itemSelector);
    if (items.length <= perPage) return; // No pagination needed

    paginationState[containerId] = {
        currentPage: 1,
        perPage: perPage,
        totalItems: items.length,
        totalPages: Math.ceil(items.length / perPage)
    };

    // Hide all items initially, show first page
    items.forEach((item, idx) => {
        item.dataset.paginationIdx = idx;
        item.style.display = idx < perPage ? '' : 'none';
    });

    // Create pagination controls
    const paginationHtml = createPaginationControls(containerId);
    const paginationDiv = document.createElement('div');
    paginationDiv.className = 'pagination';
    paginationDiv.id = 'pagination-' + containerId;
    paginationDiv.innerHTML = paginationHtml;
    container.appendChild(paginationDiv);

    updatePaginationDisplay(containerId);
}

function createPaginationControls(containerId) {
    const state = paginationState[containerId];
    return `
        <button class="pagination-btn" onclick="goToPage('${containerId}', 1)" title="First">&laquo;</button>
        <button class="pagination-btn" onclick="goToPage('${containerId}', ${state.currentPage - 1})" title="Previous">&lsaquo;</button>
        <span class="pagination-info">
            Page <span id="page-num-${containerId}">${state.currentPage}</span> of ${state.totalPages}
            (${state.totalItems} items)
        </span>
        <button class="pagination-btn" onclick="goToPage('${containerId}', ${state.currentPage + 1})" title="Next">&rsaquo;</button>
        <button class="pagination-btn" onclick="goToPage('${containerId}', ${state.totalPages})" title="Last">&raquo;</button>
        <div class="pagination-jump">
            <input type="number" min="1" max="${state.totalPages}" value="${state.currentPage}"
                onchange="goToPage('${containerId}', parseInt(this.value) || 1)"
                onkeypress="if(event.key==='Enter')goToPage('${containerId}', parseInt(this.value) || 1)">
        </div>
    `;
}

function goToPage(containerId, page) {
    const state = paginationState[containerId];
    if (!state) return;

    // Clamp page to valid range
    page = Math.max(1, Math.min(state.totalPages, page));
    state.currentPage = page;

    // Show/hide items for current page
    const container = document.getElementById(containerId);
    const items = container.querySelectorAll('[data-pagination-idx]');
    const start = (page - 1) * state.perPage;
    const end = start + state.perPage;

    items.forEach((item, idx) => {
        item.style.display = (idx >= start && idx < end) ? '' : 'none';
    });

    updatePaginationDisplay(containerId);
}

function updatePaginationDisplay(containerId) {
    const state = paginationState[containerId];
    const pageNum = document.getElementById('page-num-' + containerId);
    if (pageNum) pageNum.textContent = state.currentPage;

    const input = document.querySelector('#pagination-' + containerId + ' input');
    if (input) input.value = state.currentPage;
}

// ═══════════════════ Policy Viewer ═══════════════════
let policyData = {};

function registerPolicy(policyArn, policyJson, issues) {
    policyData[policyArn] = { json: policyJson, issues: issues || [] };
}

function viewPolicy(policyArn, issues) {
    const viewer = document.getElementById('policy-viewer');
    const title = document.querySelector('.policy-viewer-title');
    const arn = document.querySelector('.policy-viewer-arn');
    const body = document.querySelector('.policy-code');

    if (!viewer || !policyData[policyArn]) {
        showToast('Policy data not available');
        return;
    }

    const data = policyData[policyArn];
    const policyName = policyArn.split('/').pop() || policyArn.split(':').pop();

    title.innerHTML = '<span style="color:var(--olive)">📜</span> ' + escapeHtml(policyName);
    arn.textContent = policyArn;

    // Highlight the policy JSON with syntax highlighting and issue markers
    body.innerHTML = highlightPolicyJson(data.json, data.issues);

    viewer.classList.add('visible');
    document.body.style.overflow = 'hidden';
}

function closePolicy() {
    const viewer = document.getElementById('policy-viewer');
    if (viewer) {
        viewer.classList.remove('visible');
        document.body.style.overflow = '';
    }
}

function highlightPolicyJson(jsonStr, issues) {
    // First, pretty-print the JSON
    let obj;
    try {
        obj = typeof jsonStr === 'string' ? JSON.parse(jsonStr) : jsonStr;
    } catch (e) {
        return escapeHtml(jsonStr);
    }

    const formatted = JSON.stringify(obj, null, 2);
    const lines = formatted.split('\\n');
    const issueActions = new Set(issues.map(i => i.toLowerCase()));

    // Process each line
    return lines.map(line => {
        let escaped = escapeHtml(line);

        // Check if this line contains an issue action
        let hasIssue = false;
        issueActions.forEach(action => {
            if (line.toLowerCase().includes('"' + action + '"') ||
                line.toLowerCase().includes('": "' + action) ||
                line.toLowerCase().includes('"*"') ||
                (action.includes(':') && line.toLowerCase().includes(action))) {
                hasIssue = true;
            }
        });

        // Check for dangerous patterns
        const dangerousPatterns = ['"*"', '"iam:*"', '"s3:*"', '"ec2:*"', '"lambda:*"',
            'AttachRolePolicy', 'AttachUserPolicy', 'PutRolePolicy', 'PutUserPolicy',
            'CreateAccessKey', 'CreateLoginProfile', 'UpdateAssumeRolePolicy',
            'PassRole', 'AssumeRole', 'CreatePolicyVersion', 'SetDefaultPolicyVersion'];
        dangerousPatterns.forEach(pattern => {
            if (line.includes(pattern)) hasIssue = true;
        });

        // Apply syntax highlighting
        escaped = escaped
            .replace(/"([^"]+)":/g, '<span class="key">"$1"</span>:')
            .replace(/: "([^"]+)"/g, ': <span class="string">"$1"</span>')
            .replace(/: (true|false)/g, ': <span class="boolean">$1</span>')
            .replace(/: (null)/g, ': <span class="null">$1</span>')
            .replace(/: (\\d+)/g, ': <span class="number">$1</span>');

        // Wrap dangerous values
        if (hasIssue) {
            return '<span class="issue-line">' + escaped + '</span>';
        }

        return escaped;
    }).join('\\n');
}

function copyPolicyJson() {
    const body = document.querySelector('.policy-code');
    if (body) {
        const text = body.textContent;
        navigator.clipboard.writeText(text).then(() => showToast('Policy JSON copied'));
    }
}

// ═══════════════════ Expand all on load ═══════════════════
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.account-section').forEach((section, i) => {
        if (i === 0) toggleAccount(section.id.replace('as-', ''));
    });

    // Add click handlers for ARN copying
    document.querySelectorAll('[data-arn]').forEach(el => {
        el.addEventListener('click', (e) => {
            copyArn(el.dataset.arn, e);
        });
    });

    // Close policy viewer on escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closePolicy();
    });

    // Close policy viewer on backdrop click
    const viewer = document.getElementById('policy-viewer');
    if (viewer) {
        viewer.addEventListener('click', (e) => {
            if (e.target === viewer) closePolicy();
        });
    }
});
"""
