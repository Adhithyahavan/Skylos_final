import sys
import subprocess
import os

# Programmatically ensure python-docx is installed
try:
    import docx
except ImportError:
    print("python-docx not found. Installing python-docx...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "python-docx"])
        import docx
    except Exception as e:
        print(f"Error installing python-docx: {e}")
        sys.exit(1)

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

# --- Color Scheme Definitions ---
HEX_PRIMARY = "1A365D"    # Deep Blue
HEX_SECONDARY = "0D9488"  # Teal
HEX_TEXT = "374151"       # Charcoal
HEX_BG_LIGHT = "F3F4F6"   # Very Light Grey
HEX_BORDER = "E5E7EB"     # Light grey border

RGB_PRIMARY = RGBColor(0x1A, 0x36, 0x5D)
RGB_SECONDARY = RGBColor(0x0D, 0x94, 0x88)
RGB_TEXT = RGBColor(0x37, 0x41, 0x51)
RGB_MUTED = RGBColor(0x6B, 0x72, 0x80)

def set_cell_shading(cell, color_hex):
    """Set the background color of a cell."""
    shading_xml = f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>'
    cell._tc.get_or_add_tcPr().append(parse_xml(shading_xml))

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set internal padding for a cell in dxa (1 pt = 20 dxa)."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def set_cell_borders(cell, top=None, bottom=None, left=None, right=None):
    """Set borders for a specific cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcBorders = OxmlElement('w:tcBorders')
    
    borders = {'top': top, 'bottom': bottom, 'left': left, 'right': right}
    for border_name, border_props in borders.items():
        if border_props is not None:
            node = OxmlElement(f'w:{border_name}')
            node.set(qn('w:val'), border_props.get('val', 'single'))
            node.set(qn('w:sz'), str(border_props.get('sz', 4)))
            node.set(qn('w:space'), '0')
            node.set(qn('w:color'), border_props.get('color', 'auto'))
            tcBorders.append(node)
        else:
            node = OxmlElement(f'w:{border_name}')
            node.set(qn('w:val'), 'none')
            tcBorders.append(node)
    tcPr.append(tcBorders)

def add_heading_styled(doc, text, level, space_before=18, space_after=6):
    """Add a heading with custom typography and spacing."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(space_before)
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.keep_with_next = True
    
    run = p.add_run(text)
    run.font.name = 'Segoe UI'
    run.bold = True
    
    if level == 1:
        run.font.size = Pt(16)
        run.font.color.rgb = RGB_PRIMARY
        # Add a subtle bottom border or accent text line in next paragraph
    elif level == 2:
        run.font.size = Pt(13)
        run.font.color.rgb = RGB_SECONDARY
    elif level == 3:
        run.font.size = Pt(11.5)
        run.font.color.rgb = RGB_TEXT
        run.italic = True
        
    return p

def add_paragraph_styled(doc, text="", space_after=6, bold_prefix=None, indent_level=0):
    """Add a body paragraph with custom typography."""
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing = 1.15
    if indent_level > 0:
        p.paragraph_format.left_indent = Inches(0.25 * indent_level)
        
    if bold_prefix:
        r_prefix = p.add_run(bold_prefix)
        r_prefix.font.name = 'Segoe UI'
        r_prefix.font.size = Pt(10.5)
        r_prefix.bold = True
        r_prefix.font.color.rgb = RGB_TEXT
        
    run = p.add_run(text)
    run.font.name = 'Segoe UI'
    run.font.size = Pt(10.5)
    run.font.color.rgb = RGB_TEXT
    return p

def add_bullet_styled(doc, text, bold_prefix=None, indent_level=1):
    """Add a professional bullet point."""
    p = doc.add_paragraph(style='List Bullet')
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.line_spacing = 1.15
    p.paragraph_format.left_indent = Inches(0.25 * indent_level)
    
    if bold_prefix:
        r_prefix = p.add_run(bold_prefix)
        r_prefix.font.name = 'Segoe UI'
        r_prefix.font.size = Pt(10.5)
        r_prefix.bold = True
        r_prefix.font.color.rgb = RGB_TEXT
        
    run = p.add_run(text)
    run.font.name = 'Segoe UI'
    run.font.size = Pt(10.5)
    run.font.color.rgb = RGB_TEXT
    return p

def add_callout_box(doc, title, text_lines):
    """Add a shaded callout box (single-cell table) with a thick left border."""
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    cell = table.cell(0, 0)
    cell.width = Inches(6.5)
    set_cell_shading(cell, HEX_BG_LIGHT)
    set_cell_margins(cell, top=140, bottom=140, left=200, right=200)
    
    # Left border: thick teal. Other borders: none.
    border_props = {'val': 'single', 'sz': 24, 'color': HEX_SECONDARY}
    set_cell_borders(cell, left=border_props, top=None, bottom=None, right=None)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(4)
    run_title = p.add_run(title)
    run_title.font.name = 'Segoe UI'
    run_title.font.size = Pt(11)
    run_title.bold = True
    run_title.font.color.rgb = RGB_PRIMARY
    
    for line in text_lines:
        p_line = cell.add_paragraph()
        p_line.paragraph_format.space_after = Pt(2)
        p_line.paragraph_format.line_spacing = 1.1
        run_line = p_line.add_run(line)
        run_line.font.name = 'Consolas' # Code font
        run_line.font.size = Pt(9.5)
        run_line.font.color.rgb = RGB_TEXT
    
    # Empty spacing after table
    p_spacer = doc.add_paragraph()
    p_spacer.paragraph_format.space_before = Pt(6)
    p_spacer.paragraph_format.space_after = Pt(6)

def build_document():
    doc = Document()
    
    # Set standard margins (1 inch)
    for section in doc.sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)
        
    # --- Title Page (Cover Banner Style) ---
    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    title_p.paragraph_format.space_before = Pt(40)
    title_p.paragraph_format.space_after = Pt(4)
    
    title_run = title_p.add_run("AI-SIEM GUARDIAN")
    title_run.font.name = 'Segoe UI'
    title_run.font.size = Pt(32)
    title_run.bold = True
    title_run.font.color.rgb = RGB_PRIMARY
    
    subtitle_p = doc.add_paragraph()
    subtitle_p.paragraph_format.space_after = Pt(24)
    sub_run = subtitle_p.add_run("Lightweight AI-Powered Security Information and Event Management Platform\nComprehensive Project Documentation & Core Algorithm Analysis")
    sub_run.font.name = 'Segoe UI'
    sub_run.font.size = Pt(13)
    sub_run.font.color.rgb = RGB_SECONDARY
    
    desc_p = doc.add_paragraph()
    desc_p.paragraph_format.space_after = Pt(180) # Large spacing push
    drur = desc_p.add_run("This technical document details the design choices, architectural data workflows, and cyber detection algorithms powering the open-source AI-SIEM Guardian security monitoring platform.")
    drur.font.name = 'Segoe UI'
    drur.font.size = Pt(10.5)
    drur.italic = True
    drur.font.color.rgb = RGB_MUTED
    
    meta_p = doc.add_paragraph()
    meta_p.paragraph_format.space_after = Pt(6)
    meta_run = meta_p.add_run("Document Scope:")
    meta_run.bold = True
    meta_run.font.name = 'Segoe UI'
    meta_run.font.size = Pt(10)
    
    scopes = [
        "System Architecture & Component Hierarchies",
        "Ingestion Pipeline & Log Telemetry Enrichment",
        "Machine Learning Anomaly Detection using Isolation Forest",
        "Deterministic Rule-Based Detection Fallbacks & Incident Signatures",
        "Network Packet Sniffing & Heuristics Monitoring Engine",
        "Attack Simulation Framework & Pipeline Verification",
    ]
    for s in scopes:
        add_bullet_styled(doc, s, indent_level=1)
        
    doc.add_page_break()
    
    # ==========================================
    # SECTION 1: EXECUTIVE SUMMARY
    # ==========================================
    add_heading_styled(doc, "1. Executive Summary", 1)
    
    add_paragraph_styled(doc, 
        "Modern enterprise security environments rely heavily on Security Information and Event Management (SIEM) solutions to centralize log feeds, detect security breaches, and coordinate analyst incidents. Traditional platforms like Splunk or Elastic Security, while powerful, introduce substantial operational overhead, dependency on high-specification clusters, and complex proprietary query structures. This raises barriers to entry for local testing, educational laboratories, and lightweight developer operations.",
        space_after=8
    )
    
    add_paragraph_styled(doc, 
        "AI-SIEM Guardian represents a lightweight, modular, and locally runnable Security Information and Event Management platform. It captures the essential features of an enterprise-grade SIEM platform—specifically, real-time log ingestion, metadata enrichment, rule-based heuristics, machine learning anomaly detection, localized persistent storage, real-time client state broadcast, and an integrated visualization interface. By combining a lightweight FastAPI backend, standard database modeling, scikit-learn models, and a TypeScript-backed React dashboard, AI-SIEM Guardian demonstrates a developer-friendly framework for real-world cyber threat monitoring.",
        space_after=12
    )
    
    # ==========================================
    # SECTION 2: SYSTEM ARCHITECTURE
    # ==========================================
    add_heading_styled(doc, "2. System Architecture & Component Design", 1)
    
    add_paragraph_styled(doc, 
        "The project is structured with a decoupled, three-tier modular architecture designed for high scalability, fault tolerance, and independent component testing. The system utilizes continuous background agents to gather telemetry, a FastAPI service layer to run detections and serve queries, and a modern single-page-application (SPA) client for analyst coordination.",
        space_after=8
    )
    
    add_heading_styled(doc, "2.1 Telemetry Gathering Agents", 2)
    add_paragraph_styled(doc, 
        "Telemetry ingestion is divided into two specialized network/system daemon loggers:",
        space_after=4
    )
    add_bullet_styled(doc, 
        "Simulates or pulls active operating system event logs (logins, session terminations, privilege mutations, and operational warnings). It integrates a robust offline storage mechanism: if the FastAPI central backend becomes unreachable due to network segregation or service downtime, the agent caches outgoing events locally inside logs_cache.json. Upon backend recovery, it performs block-upload batch synchronizations to prevent telemetry loss.",
        bold_prefix="System Log Agent (system_log_agent.py): "
    )
    add_bullet_styled(doc, 
        "Performs deep packet sniffing using the Python Scapy library to extract transfer statistics. When the target operating system lacks underlying packet capture drivers (such as Windows machines missing Npcap), the agent triggers an intelligent simulation fallback, generating mock network activity involving specific safe (LAN) and suspicious (external) IP address ranges to ensure test suite continuity.",
        bold_prefix="Network Traffic Agent (network_agent.py): "
    )
    
    add_heading_styled(doc, "2.2 Central API Gateway (FastAPI Backend)", 2)
    add_paragraph_styled(doc, 
        "The FastAPI central backend serves as the core orchestration engine, routing requests and managing critical state processes:",
        space_after=4
    )
    add_bullet_styled(doc, "Validates input telemetry schemas using strict Pydantic parsing structures, preventing database injection or schema poisoning.")
    add_bullet_styled(doc, "Coordinates the Log Enrichment Pipeline, querying active database connections to supplement logs with contextual metrics.")
    add_bullet_styled(doc, "Hosts the AI Anomaly Detection Engine, managing inference execution and background model retraining lifecycles.")
    add_bullet_styled(doc, "Operates a WebSocket Broadcast Manager, which pushes newly ingested logs and security alerts instantly to connected analyst browsers, maintaining sub-second user interface updates.")
    add_bullet_styled(doc, "Exposes REST endpoints for user authentication, security log tables, network capture triggers, and mock attack simulations.")
    
    add_heading_styled(doc, "2.3 Analytical Client (React Dashboard)", 2)
    add_paragraph_styled(doc, 
        "The user-facing dashboard is designed for high visual clarity, utilizing a professional dark mode interface tailored to Security Operation Centers (SOCs):",
        space_after=4
    )
    add_bullet_styled(doc, "Built using Vite, React, TypeScript, and styled with Tailwind CSS.", bold_prefix="Performance: ")
    add_bullet_styled(doc, "Integrates interactive graphs representing user login spikes and alert volumes over time.", bold_prefix="Data Visualization: ")
    add_bullet_styled(doc, "Uses a dedicated WebSocket connection that listens for incoming alerts and flashes overlay warnings (toasts) without page refreshes.", bold_prefix="Live-Feed Incidents: ")
    add_bullet_styled(doc, "Provides lists of anomalous events, active alerts, top attacking IPs, and a interactive simulator control board.", bold_prefix="Interface Scope: ")

    # ==========================================
    # SECTION 3: CORE ALGORITHMS & THREAT DETECTION
    # ==========================================
    doc.add_page_break()
    add_heading_styled(doc, "3. Core Detection Algorithms & Machine Learning", 1)
    
    add_paragraph_styled(doc, 
        "To achieve robust security monitoring, AI-SIEM Guardian implements a hybrid analysis system. Telemetry is evaluated using a machine learning classifier, a rule-based fallback heuristic compiler, and a protocol-level network scanner. This ensures immediate detection during cold starts and accurate behavioral classification once historical data accumulates.",
        space_after=8
    )
    
    add_heading_styled(doc, "3.1 Log Enrichment & Feature Vectors", 2)
    add_paragraph_styled(doc, 
        "When raw logs arrive at the ingestion endpoint, they lack the historical context needed to identify complex threat campaigns. To resolve this, the system queries the relational database in real-time to compute three additional metadata features. A 4-dimensional feature vector is compiled structure-by-structure:",
        space_after=6
    )
    
    # Add a table showing features
    table = doc.add_table(rows=1, cols=3)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    # Style table headers
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = "Feature Variable"
    hdr_cells[1].text = "Technical Type"
    hdr_cells[2].text = "Operational Description / Context"
    for i, cell in enumerate(hdr_cells):
        cell.width = Inches(1.8) if i < 2 else Inches(2.9)
        set_cell_shading(cell, HEX_PRIMARY)
        set_cell_margins(cell, top=120, bottom=120, left=120, right=120)
        p = cell.paragraphs[0]
        p.runs[0].font.name = 'Segoe UI'
        p.runs[0].font.size = Pt(10)
        p.runs[0].bold = True
        p.runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        
    features_list = [
        ("failed_attempts", "Integer (0+)", "The number of sequential failed passwords logged for the given user Account. A high count suggests active password guessing."),
        ("login_frequency", "Float (0.0 to 100.0)", "Computed by querying the database for all logs matching the User within the recent historical log limits. Detects automation."),
        ("ip_activity_rate", "Float (0.0 to 200.0)", "Computed by counting prior event entries matching the source IP. Helps identify rapid API abuse or scanning activity."),
        ("hour_of_day", "Integer (0 to 23)", "Extracted directly from the server system timestamp in UTC. Allows the model to recognize nighttime logins or anomalies based on local shifts.")
    ]
    
    for idx, (fav, typ, desc) in enumerate(features_list):
        row = table.add_row()
        row.cells[0].text = fav
        row.cells[1].text = typ
        row.cells[2].text = desc
        for i, cell in enumerate(row.cells):
            cell.width = Inches(1.8) if i < 2 else Inches(2.9)
            set_cell_margins(cell, top=80, bottom=80, left=120, right=120)
            set_cell_shading(cell, HEX_BG_LIGHT if idx % 2 == 1 else "FFFFFF")
            # Set border
            border_props = {'val': 'single', 'sz': 4, 'color': HEX_BORDER}
            set_cell_borders(cell, top=border_props, bottom=border_props, left=border_props, right=border_props)
            p = cell.paragraphs[0]
            p.runs[0].font.name = 'Segoe UI'
            p.runs[0].font.size = Pt(9.5)
            p.runs[0].font.color.rgb = RGB_TEXT
            if i == 0:
                p.runs[0].bold = True
                
    doc.add_paragraph().paragraph_format.space_after = Pt(10) # spacing
    
    add_heading_styled(doc, "3.2 Unsupervised Anomaly Detection: Isolation Forest", 2)
    add_paragraph_styled(doc, 
        "At the core of the AI-SIEM engine resides scikit-learn's Isolation Forest algorithm. Unlike traditional classification or clustering methods (which define normal boundaries and flag anything that falls outside as an outlier), the Isolation Forest isolates anomalies directly based on decision trees.",
        space_after=6
    )
    
    add_paragraph_styled(doc, 
        "Mathematics & Mechanism:",
        space_after=4,
        bold_prefix="Methodology Description: "
    )
    add_bullet_styled(doc, "The algorithm constructs an ensemble of Isolation Trees (iTrees) by recursively partitioning the feature space.", indent_level=1)
    add_bullet_styled(doc, "In each split, a feature is selected at random from the 4-dimensional vector, and a split point is chosen randomly between the feature's minimum and maximum values.", indent_level=1)
    add_bullet_styled(doc, "Because anomalous points possess unique characteristics (such as 10 failed logins at 3:00 AM combined with high activity rates), they require significantly fewer splits to isolate than clustered, normal data. Consequently, their path lengths in the trees are much shorter.", indent_level=1)
    add_bullet_styled(doc, "An anomaly score is calculated based on this average path length. Observations yielding scores closer to 1.0 are categorized as anomalies, whereas scores significantly below 0.5 indicate normal behavior.", indent_level=1)
    
    add_paragraph_styled(doc, 
        "Model Integration & Hyperparameters:",
        space_after=4,
        bold_prefix="Implementation Details: "
    )
    add_bullet_styled(doc, "The number of trees in the forest. A higher value leads to a more stable decision boundary.", bold_prefix="n_estimators = 100: ")
    add_bullet_styled(doc, "Determines the proportion of outliers in the dataset, governed by backend configuration config.py. Typically set between 0.01 and 0.05. This dictates the decision threshold for flagging a log as anomalous.", bold_prefix="contamination = settings.ANOMALY_CONTAMINATION: ")
    add_bullet_styled(doc, "Guarantees reproducible splits when retraining models during developer audits.", bold_prefix="random_state = 42: ")
    add_bullet_styled(doc, "Instructs scikit-learn to utilize all available CPU threads of the host system, ensuring fast parallelized calculations.", bold_prefix="n_jobs = -1: ")
    
    add_paragraph_styled(doc, 
        "State machine & Retraining Lifecycle:",
        space_after=4,
        bold_prefix="Operational Mechanics: "
    )
    add_bullet_styled(doc, "During the initial boot of the backend database, there are insufficient logs. The Isolation Forest requires a minimum of MIN_TRAINING_SAMPLES (default 20 logs) to train. Until this count is reached, she defaults automatically to rule-based fallback detection.", indent_level=1)
    add_bullet_styled(doc, "As new telemetry logs pass the ingestion pipeline, the system maintains a running log count. Every 50 logs ingested, FastAPI triggers a background retraining thread.", indent_level=1)
    add_bullet_styled(doc, "The retraining script fetches the latest 500 logs from the SQLite/Postgres database, extracts the 4-dimensional features, and fits a fresh IsolationForest instance. This ensures the model adapts dynamically to changing login behaviors and activity shifts.", indent_level=1)

    add_heading_styled(doc, "3.3 Rule-Based Heuristic Fallback Engine", 2)
    add_paragraph_styled(doc, 
        "To guarantee security monitoring is active immediately upon startup, the system incorporates a fallback heuristic engine. When the Isolation Forest is not yet trained, the system classifies anomalies using deterministic threshold checks:",
        space_after=6
    )
    
    # Code Callout box for rule based fallback
    add_callout_box(doc, "Rule-Based Threshold Fallbacks", [
        "# If ML is not trained, fallback rule evaluates True for any match:",
        "if failed_attempts >= 5:          => Trigger Anomaly (Brute Force suspected)",
        "if login_frequency > 20:          => Trigger Anomaly (Automation script suspected)",
        "if ip_activity_rate > 50:         => Trigger Anomaly (Port scanning or Scraping)",
        "if (hour < 4 or hour > 23) and failed_attempts >= 2: ",
        "                                  => Trigger Anomaly (Off-hours Bruteforce suspected)"
    ])
    
    add_heading_styled(doc, "3.4 Threat Incident Classification Rules", 2)
    add_paragraph_styled(doc, 
        "When an anomaly is caught (via ML or fallback rules), the Log Processor enriches the alert with a specific category to help analysts respond quickly. AI-SIEM Guardian assigns categories using key indicator patterns:",
        space_after=4
    )
    add_bullet_styled(doc, "Triggered when failed attempts reach or exceed 5. This indicates a targeted attempt to guess a single password.", bold_prefix="Brute Force (brute_force): ")
    add_bullet_styled(doc, "Triggered when the user log rate exceeds 30 logins in the tracking window, indicating high-frequency API automation.", bold_prefix="High Frequency (high_frequency): ")
    add_bullet_styled(doc, "Triggered when an IP makes more than 80 requests in a short interval. This indicates automated brute force across several accounts.", bold_prefix="Credential Stuffing (credential_stuffing): ")
    add_bullet_styled(doc, "Assigned when the network agent detects packets scanned across multiple sequential port IDs.", bold_prefix="Port Scan (port_scan): ")
    add_bullet_styled(doc, "Assigned when event telemetry indicates impossible travel, such as logins by the same user from different geographical locations in seconds.", bold_prefix="Geographical Anomaly (geo_anomaly): ")

    # ==========================================
    # SECTION 4: NETWORK CAPTURE & SECURITY
    # ==========================================
    add_heading_styled(doc, "3.5 Network Analysis & Packet Heuristics", 2)
    add_paragraph_styled(doc, 
        "While the system log agent focuses on authentication and action logs, the Network Analyzer monitors transit traffic. It runs packet capture loops that evaluate telemetry using these signatures:",
        space_after=4
    )
    add_bullet_styled(doc, "Packets are evaluated by source IP. If any IP generates more than 1,000 packets within the sampling interval, it is flagged as suspicious, alerting analysts to potential flooding or Denial of Service (DoS) attacks.", bold_prefix="Volume Rate Limiting: ")
    add_bullet_styled(doc, "Classifies packets by protocol (TCP, UDP, ICMP, DNS, HTTP, HTTPS) to build a distribution chart. Anomalous spikes in ICMP or UDP can point to scanning or UDP flood attempts.", bold_prefix="Protocol Segmentation: ")

    # ==========================================
    # SECTION 4: ATTACK SIMULATION ENGINE
    # ==========================================
    doc.add_page_break()
    add_heading_styled(doc, "4. Attack Simulation Framework", 1)
    
    add_paragraph_styled(doc, 
        "To verify that the ingestion, ML detection, database storage, and WebSocket pipeline work correctly, the platform includes a testing module in attack_simulator.py. Analysts can trigger five simulated attacks from the dashboard:",
        space_after=8
    )
    
    add_bullet_styled(doc, 
        "Simulates a brute-force login attack. It generates 10 sequential log entries from a single external attacker IP (e.g., 203.0.113.42) targeting a single username (e.g., admin or root) with failed attempt counts incrementing from 1 to 10. The AI engine flags this quickly due to the high failed attempt rate and unusual IP activity.",
        bold_prefix="1. Brute-Force Simulator: "
    )
    add_bullet_styled(doc, 
        "Simulates a port scanning attack. It generates logs representing rapid connections to 20-50 random ports from a single suspicious source IP. This triggers anomalies based on the sudden spike in IP activity rate.",
        bold_prefix="2. Port Scan Simulator: "
    )
    add_bullet_styled(doc, 
        "Simulates credential stuffing. It generates 15 login attempts under different usernames (admin, root, devops, svc_account) from a single suspicious IP to evaluate how the system detects distributed attacks from a single source.",
        bold_prefix="3. Credential Stuffing Simulator: "
    )
    add_bullet_styled(doc, 
        "Simulates a geographical anomaly (impossible travel). It generates two login logs for the same user in quick succession from different countries (e.g. BR and KR), flagging the sudden geographical shift.",
        bold_prefix="4. Impossible Travel Simulator: "
    )
    add_bullet_styled(doc, 
        "Simulates a high-frequency login attack. It generates 25 rapid login attempts with low failures but high IP activity rates, testing the system's ability to detect high-speed, automated scripts.",
        bold_prefix="5. High-Frequency Simulator: "
    )

    # ==========================================
    # SECTION 5: SCHEMA REPRESENTATION
    # ==========================================
    add_heading_styled(doc, "5. Database Schema & Data Models", 1)
    add_paragraph_styled(doc, 
        "The system stores all analytical logs and alerts in a relational SQLite database (siem_guardian.db), managed via SQLAlchemy. This design ensures that raw telemetry can be audit-logged and analyzed after security incidents occur.",
        space_after=8
    )
    
    table_db = doc.add_table(rows=1, cols=4)
    table_db.alignment = WD_TABLE_ALIGNMENT.CENTER
    table_db.autofit = False
    
    hdr_db_cells = table_db.rows[0].cells
    hdr_db_cells[0].text = "SQL Table Name"
    hdr_db_cells[1].text = "Core Columns"
    hdr_db_cells[2].text = "SQL Types"
    hdr_db_cells[3].text = "Purpose / Relational Context"
    for i, cell in enumerate(hdr_db_cells):
        cell.width = Inches(1.3) if i in [0, 2] else (Inches(1.7) if i == 1 else Inches(2.2))
        set_cell_shading(cell, HEX_PRIMARY)
        set_cell_margins(cell, top=120, bottom=120, left=120, right=120)
        p = cell.paragraphs[0]
        p.runs[0].font.name = 'Segoe UI'
        p.runs[0].font.size = Pt(10)
        p.runs[0].bold = True
        p.runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        
    db_list = [
        ("users", "id, username, email, hashed_password, role, is_active, created_at", "INT, VARCHAR, VARCHAR, VARCHAR, VARCHAR, BOOL, DATETIME", "Stores analyst and admin accounts, supporting Role-Based Access Control (RBAC)."),
        ("logs", "id, user, ip, event_type, failed_attempts, login_frequency, ip_activity_rate, anomaly, raw_data, timestamp", "INT, VARCHAR, VARCHAR, VARCHAR, INT, FLOAT, FLOAT, BOOL, TEXT, DATETIME", "Stores enriched system logs. Anomalous entries have the anomaly flag set to True."),
        ("alerts", "id, log_id, severity, message, ip, alert_type, acknowledged, timestamp", "INT, INT, VARCHAR, TEXT, VARCHAR, VARCHAR, BOOL, DATETIME", "Stores security alerts triggered by anomalies. Tracks analyst acknowledgment state."),
        ("network_activity", "id, ip, packets, bytes_transferred, protocol, suspicious, timestamp", "INT, VARCHAR, INT, INT, VARCHAR, BOOL, DATETIME", "Stores network capture statistics collected by the Scapy agent."),
        ("audit_logs", "id, user_id, action, details, timestamp", "INT, INT, VARCHAR, TEXT, DATETIME", "Logs analyst actions, such as marking alerts as acknowledged, for security auditing.")
    ]
    
    for idx, (tbl, cols, typs, purpose) in enumerate(db_list):
        row = table_db.add_row()
        row.cells[0].text = tbl
        row.cells[1].text = cols
        row.cells[2].text = typs
        row.cells[3].text = purpose
        for i, cell in enumerate(row.cells):
            cell.width = Inches(1.3) if i in [0, 2] else (Inches(1.7) if i == 1 else Inches(2.2))
            set_cell_margins(cell, top=80, bottom=80, left=120, right=120)
            set_cell_shading(cell, HEX_BG_LIGHT if idx % 2 == 1 else "FFFFFF")
            border_props = {'val': 'single', 'sz': 4, 'color': HEX_BORDER}
            set_cell_borders(cell, top=border_props, bottom=border_props, left=border_props, right=border_props)
            p = cell.paragraphs[0]
            p.runs[0].font.name = 'Segoe UI'
            p.runs[0].font.size = Pt(9)
            p.runs[0].font.color.rgb = RGB_TEXT
            if i == 0:
                p.runs[0].bold = True
                
    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # ==========================================
    # SECTION 6: DESIGN PRINCIPLES
    # ==========================================
    add_heading_styled(doc, "6. SOC Interface & Design Principles", 1)
    add_paragraph_styled(doc, 
        "A critical challenge in modern SOC operations is alert fatigue. If an interface is cluttered or confusing, analysts are more likely to miss real threats. To address this, the AI-SIEM Guardian dashboard is built on three core design principles:",
        space_after=4
    )
    add_bullet_styled(doc, "The dashboard uses a custom dark theme with high-contrast indicator colors (Red for high severity, Yellow for warning, Green for operational status) to help analysts prioritize alerts under different lighting conditions.", bold_prefix="1. Visual Hierarchy: ")
    add_bullet_styled(doc, "Leverages WebSockets to push alerts to the browser instantly. This ensures analysts see incoming threats without manual page refreshes, reducing response latency.", bold_prefix="2. Real-Time Response: ")
    add_bullet_styled(doc, "Important metrics (total anomalies, active alerts, traffic rates, and historical timelines) are visible on a single page, giving analysts an immediate overview of the system's security posture.", bold_prefix="3. Unified Display: ")
    
    # Save the file
    doc_path = "AI-SIEM_Guardian_Documentation.docx"
    doc.save(doc_path)
    print(f"Success: Documentation created at {os.path.abspath(doc_path)}")

if __name__ == "__main__":
    build_document()
