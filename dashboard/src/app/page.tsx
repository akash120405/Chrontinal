"use client";

import { useState } from "react";
import Link from "next/link";
import { Activity, ArrowRight, ArrowUpRight, Bot, FileText, GitBranch, LockKeyhole, Menu, Radio, Search, Shield, X } from "lucide-react";
import styles from "./landing.module.css";

const navigation = [
  ["Overview", "#overview"], ["Platform", "#platform"], ["Workflow", "#workflow"],
  ["Explore modules", "#modules"], ["Get started", "#get-started"],
] as const;

const capabilities = [
  { number: "01", icon: Radio, title: "Live feed", description: "Follow incoming security events from one focused view.", href: "/live-feed" },
  { number: "02", icon: Shield, title: "Alert triage", description: "Prioritize signals and move from alert to investigation.", href: "/alerts" },
  { number: "03", icon: GitBranch, title: "Attack graph", description: "See relationships between entities, events, and threats.", href: "/attack-graph" },
  { number: "04", icon: Search, title: "Investigations", description: "Bring evidence, context, and response into one workflow.", href: "/investigations" },
  { number: "05", icon: Bot, title: "AI assistance", description: "Explore assisted analysis and explainable results.", href: "/ai-agents" },
  { number: "06", icon: FileText, title: "Reports & evidence", description: "Keep findings organized and ready to share.", href: "/reports" },
] as const;

const modules = [
  ["01", "Security dashboard", "Your operational view", "/dashboard"],
  ["02", "Threat intelligence", "Context around emerging risks", "/threat-intel"],
  ["03", "Semantic search", "Find related events faster", "/search"],
  ["04", "Chain of custody", "Track evidence integrity", "/chain-of-custody"],
] as const;

function SignalGraphic() {
  return <div className={styles.signalGraphic} aria-hidden="true">
    <div className={styles.ambientOrb} />
    <svg viewBox="0 0 700 660" className={styles.graphicSvg} role="presentation">
      <defs>
        <radialGradient id="coreGradient"><stop stopColor="#f1aeff" /><stop offset=".28" stopColor="#b748f0" stopOpacity=".7" /><stop offset="1" stopColor="#21103f" stopOpacity="0" /></radialGradient>
        <linearGradient id="edgeGradient" x1="0" y1="0" x2="1" y2="1"><stop stopColor="#ffadf7" /><stop offset=".5" stopColor="#c03be8" /><stop offset="1" stopColor="#733dff" /></linearGradient>
        <filter id="edgeGlow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="7" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
      </defs>
      <circle cx="355" cy="330" r="220" fill="url(#coreGradient)" />
      <g fill="none" stroke="#f1b6ff" strokeWidth="2" opacity=".8">
        <circle cx="355" cy="330" r="132" />
        <ellipse cx="355" cy="330" rx="136" ry="53" transform="rotate(32 355 330)" />
        <ellipse cx="355" cy="330" rx="136" ry="53" transform="rotate(95 355 330)" />
        <ellipse cx="355" cy="330" rx="136" ry="53" transform="rotate(152 355 330)" />
        <path d="M355 198 480 282 432 442 274 447 222 290Z M355 198 274 447 M480 282 222 290 M432 442 355 198" />
      </g>
      <g fill="none" stroke="url(#edgeGradient)" strokeWidth="8" strokeLinejoin="round" filter="url(#edgeGlow)">
        <path d="M352 54 604 170 576 510 320 610 94 450 118 178Z M352 54 320 610 M118 178 576 510 M604 170 94 450" />
      </g>
      <g fill="#da73f4" stroke="#ffd1ff" strokeWidth="2">
        <circle cx="352" cy="54" r="13" /><circle cx="604" cy="170" r="13" /><circle cx="576" cy="510" r="13" />
        <circle cx="320" cy="610" r="13" /><circle cx="94" cy="450" r="13" /><circle cx="118" cy="178" r="13" />
      </g>
    </svg>
    <span className={`${styles.orbitBadge} ${styles.badgeOne}`}>DETECT</span>
    <span className={`${styles.orbitBadge} ${styles.badgeTwo}`}>ANALYZE</span>
    <span className={`${styles.orbitBadge} ${styles.badgeThree}`}>RESPOND</span>
  </div>;
}

export default function Home() {
  const [menuOpen, setMenuOpen] = useState(false);
  return <div className={styles.site}>
    <header className={styles.header}>
      <Link href="#overview" className={styles.brand} aria-label="Chrontinal SOC home" onClick={() => setMenuOpen(false)}><span className={styles.brandMark}>C</span><span>chrontinal <strong>SOC</strong></span></Link>
      <button type="button" className={styles.menuToggle} aria-label={menuOpen ? "Close navigation" : "Open navigation"} aria-expanded={menuOpen} aria-controls="landing-navigation" onClick={() => setMenuOpen(!menuOpen)}>{menuOpen ? <X size={29} strokeWidth={1.4} /> : <Menu size={31} strokeWidth={1.4} />}</button>
      <Link href="/login" className={styles.headerCta} onClick={() => setMenuOpen(false)}>Enter console <ArrowUpRight size={18} /></Link>
    </header>
    <nav id="landing-navigation" className={`${styles.menuPanel} ${menuOpen ? styles.menuPanelOpen : ""}`} aria-label="Main navigation" aria-hidden={!menuOpen}>
      <div className={styles.menuAside}><span className={styles.slashLabel}>/ NAVIGATION</span><p>One workspace for the signals that matter.</p><Link href="/login" onClick={() => setMenuOpen(false)}>ENTER THE SOC <ArrowUpRight size={17} /></Link></div>
      <div className={styles.menuLinks}>{navigation.map(([label, href], index) => <Link key={href} href={href} tabIndex={menuOpen ? 0 : -1} onClick={() => setMenuOpen(false)}><span>0{index + 1}</span>{label}<ArrowUpRight size={23} /></Link>)}</div>
    </nav>
    <main>
      <section className={styles.hero} id="overview">
        <SignalGraphic />
        <div className={styles.heroTop}><p><span>/</span> A unified security operations workspace for detection, investigation, and response.</p><div><i /> SECURITY OPERATIONS PLATFORM</div></div>
        <div className={styles.heroCopy}><p className={styles.eyebrow}>INTELLIGENCE AT EVERY TURN</p><h1><span>TURN SIGNALS</span><br />INTO <em>/ ACTION /</em></h1><div className={styles.heroBottom}><div className={styles.heroButtons}><Link href="/dashboard" className={styles.primaryButton}>Explore the dashboard <ArrowUpRight size={19} /></Link><a href="#platform" className={styles.textButton}>Discover the platform <ArrowRight size={19} /></a></div><span className={styles.scrollPrompt}>SCROLL TO EXPLORE <b>↓</b></span></div></div>
      </section>

      <section className={styles.introBand}><span>01 / THE PLATFORM</span><p>Security work moves fast. Chrontinal brings the event stream, investigations, AI assistance, and evidence into a connected workspace.</p><Activity size={35} strokeWidth={1} aria-hidden="true" /></section>

      <section className={styles.platform} id="platform"><div className={styles.sectionHeading}><p className={styles.eyebrow}>/ BUILT FOR THE FULL PICTURE</p><h2>ABOUT<br /><span>/ THE SOC</span></h2><p>Move through the security workflow without losing the context behind a decision.</p></div><div className={styles.capabilityGrid}>{capabilities.map((item) => { const Icon = item.icon; return <Link href={item.href} key={item.number} className={styles.capabilityCard}><div className={styles.cardTop}><span>{item.number} / 06</span><ArrowUpRight size={20} /></div><div className={styles.cardIcon}><Icon size={30} strokeWidth={1.25} /></div><h3>{item.title}</h3><p>{item.description}</p></Link>; })}</div></section>

      <section className={styles.workflow} id="workflow"><div className={styles.workflowGlow} /><div className={styles.workflowLead}><p className={styles.eyebrow}>02 / FROM NOISE TO KNOWLEDGE</p><h2>SEE THE<br /><span>WHOLE STORY.</span></h2><p>Follow a signal from the moment it appears to the evidence and explanation behind your next move.</p><Link href="/investigations" className={styles.primaryButton}>Start investigating <ArrowUpRight size={19} /></Link></div><div className={styles.workflowSteps}><div><span>01</span><Radio size={26} strokeWidth={1.3} /><h3>Detect</h3><p>See events and alerts as they arrive.</p></div><div><span>02</span><GitBranch size={26} strokeWidth={1.3} /><h3>Connect</h3><p>Follow relationships and add context.</p></div><div><span>03</span><LockKeyhole size={26} strokeWidth={1.3} /><h3>Resolve</h3><p>Document findings and preserve evidence.</p></div></div></section>

      <section className={styles.modules} id="modules"><div className={styles.modulesIntro}><p className={styles.eyebrow}>03 / EXPLORE YOUR WORKSPACE</p><h2>ONE PLATFORM.<br /><span>EVERY ANGLE.</span></h2><p>Open the tools you need, right where the work happens.</p><span className={styles.miniOrb} aria-hidden="true" /></div><div className={styles.moduleList}>{modules.map(([number, title, detail, href]) => <Link href={href} key={number} className={styles.moduleRow}><span className={styles.moduleNumber}>{number}</span><span className={styles.moduleName}>{title}<small>{detail}</small></span><ArrowUpRight size={24} strokeWidth={1.25} /></Link>)}</div></section>

      <section className={styles.finalCta} id="get-started"><div className={styles.ctaOrb} aria-hidden="true" /><p className={styles.eyebrow}>/ READY WHEN YOU ARE</p><h2>MAKE YOUR<br /><span>NEXT MOVE</span><br />COUNT.</h2><p>Bring clarity to every signal and confidence to every response.</p><div className={styles.ctaActions}><Link href="/login" className={styles.primaryButton}>Enter the console <ArrowUpRight size={19} /></Link><Link href="/dashboard" className={styles.textButton}>View dashboard <ArrowRight size={19} /></Link></div></section>
    </main>
    <footer className={styles.footer}><Link href="#overview" className={styles.footerBrand}>CHRON<span>TINAL</span> <small>SOC</small></Link><span>Security operations, connected.</span><Link href="/login">OPEN WORKSPACE <ArrowUpRight size={15} /></Link></footer>
  </div>;
}
