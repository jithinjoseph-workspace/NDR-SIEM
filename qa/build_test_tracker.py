#!/usr/bin/env python3
"""Generates qa/NDR_Test_Case_Tracker.xlsx — an ISTQB/IEEE-829-style test case
tracker: Test Cases sheet (data-validated Status/Priority, conditional
color fill) + a Legend sheet explaining the format and a Summary sheet with
live pass/fail counts.

Re-run this script any time to regenerate the template from scratch. It does
NOT read back existing results — treat the generated file as the starting
template, then fill in Actual Result / Status / Executed By / Date by hand
(or extend this script to read prior data first, if that's ever needed).
"""

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.formatting.rule import CellIsRule
from openpyxl.utils import get_column_letter

OUT_PATH = "/home/user/Music/NDR/NDR-Demo/qa/NDR_Test_Case_Tracker.xlsx"

HEADERS = [
    "Test Case ID", "Module / Feature", "Test Scenario", "Test Case Title",
    "Description", "Preconditions", "Test Steps / Script", "Test Data",
    "Expected Result", "Actual Result", "Status", "Priority",
    "Executed By", "Execution Date", "Defect ID / Remarks",
]

COL_WIDTHS = [12, 18, 22, 26, 34, 24, 42, 22, 32, 32, 12, 10, 14, 14, 22]

# Starter set drawn from real issues found/fixed on this project — replace
# or extend freely; this just proves the format and seeds real coverage.
ROWS = [
    ("TC-001", "Threat Map", "Self-generated DNS lookup alert",
     "ip-api.com geo-lookup no longer triggers Suricata ET INFO alert",
     "Verify the Attack Intelligence Map widget uses local GeoLite2 DB instead of "
     "calling out to ip-api.com, so the engine doesn't flag its own traffic.",
     "ndr-engine deployed with GeoLite2-City.mmdb present at data/",
     "1. Open Dashboard > Attack Intelligence Map widget\n"
     "2. Capture network traffic from the ndr-engine host during widget load\n"
     "3. Inspect DNS queries made by the engine process",
     "N/A (passive observation)",
     "No DNS query for ip-api.com is made; geo data still renders correctly",
     "", "Not Executed", "High", "", "", ""),

    ("TC-002", "Evidence Bundles", "Rule-name attribution fallback",
     "Fallback rule name reflects actual detecting agent (Agent-S vs Agent-Z)",
     "When the real Suricata signature can't be recovered, the evidence bundle "
     "must not default to a generic 'Suricata IDS Alert' label regardless of "
     "which engine (Suricata/Agent-S or Zeek+Sigma/Agent-Z) produced the hit.",
     "An ndr_hits row exists with empty sigma_hits and no matching ndr_events alert row",
     "1. Open Evidence & Forensics for a bundle tagged AGENT-Z ONLY\n"
     "2. Check the 'Rules Fired' / attack summary section\n"
     "3. Confirm label is NOT 'Suricata IDS Alert'",
     "community_id of a Zeek-only correlated hit",
     "Label reads 'Agent-Z Sigma Match (rule name unavailable)' or the real rule name",
     "", "Not Executed", "Medium", "", "", ""),

    ("TC-003", "SOAR / Response", "Isolate action reports correct status",
     "Successful device isolation shows 'isolated' in UI, not 'Failed'",
     "isolate_device_handler must return status:'ok' on success so the Angular "
     "isolateIp() success check (res.status === 'ok') actually fires.",
     "A valid internal LAN IP is available as isolation target; sensor agent reachable",
     "1. Open Alerts > Attack Stories > expand an incident\n"
     "2. Click 'Isolate' on the internal (LAN) node\n"
     "3. Observe the result banner under the diagram",
     "target_ip = internal LAN IP (e.g. 192.168.1.x), enforcement=arp",
     "Banner shows '<ip> isolated' (green), not 'Failed'",
     "", "Not Executed", "Critical", "", "", ""),

    ("TC-004", "SOAR / Response", "Isolated state persists across reload",
     "Node still shows 'Isolated' after a full page refresh",
     "Isolation state must be read back from the device_isolations table on load, "
     "not just held in the browser session.",
     "TC-003 has passed at least once for a given target IP",
     "1. Isolate a host per TC-003\n"
     "2. Refresh the browser (F5)\n"
     "3. Re-open the same incident's Attack Path",
     "Same target_ip isolated in TC-003",
     "Node shows the 'Isolated' badge, Isolate button is hidden, no re-prompt to isolate",
     "", "Not Executed", "Medium", "", "", ""),

    ("TC-005", "Rules Page", "Rule list loads paginated, not all at once",
     "Initial load fetches ~20 rules; 'Load More' appends the next batch",
     "Verify GET /api/rules?limit=&offset= pagination and the Load More button "
     "on the analyst Rules page.",
     "Tenant has 1000+ SIGMA rules loaded",
     "1. Open Rules page, open browser DevTools > Network\n"
     "2. Confirm first /api/rules request includes limit=20&offset=0\n"
     "3. Click 'Load More' and confirm a second request with offset=20",
     "N/A", "Rule list grows by pageSize per click; 'Total Rules' tile still shows the true total",
     "", "Not Executed", "Low", "", "", ""),

    ("TC-006", "Rules Page", "Search falls back to full DB when not loaded",
     "Searching a rule not in the first page still finds it (or reports absence)",
     "Typed search first checks loaded rules client-side; if no match, it must "
     "query GET /api/rules?q= to check the complete rule set before saying 'not found'.",
     "A known rule name exists beyond the first loaded page (e.g. rule #500)",
     "1. Open Rules page (only first ~20 rules loaded)\n"
     "2. Type the name of a rule known to exist further down the list\n"
     "3. Observe result after debounce",
     "Rule title not present in the first 20 rows",
     "Matching rule appears (fetched via DB fallback); searching a nonexistent "
     "name shows 'No rule matching \"...\" exists'",
     "", "Not Executed", "Medium", "", "", ""),

    ("TC-007", "Auth / Access Control", "Tenant admin cannot reset super_admin password",
     "IDOR check: tenant_admin scoped to own-tenant, non-admin targets only",
     "POST /api/auth/users/:id/password, /status, /permissions and DELETE must "
     "validate the TARGET user's role/tenant, not just the caller's role.",
     "A tenant_admin account and a super_admin account (different tenant) both exist",
     "1. Log in as tenant_admin\n"
     "2. Call POST /api/auth/users/<super_admin_id>/password with a new password\n"
     "3. Also try DELETE on a user in a different tenant",
     "target = super_admin user id from another tenant",
     "Request is rejected with 403 Forbidden in all cases",
     "", "Not Executed", "Critical", "", "", ""),

    ("TC-008", "Auth / MFA", "MFA verify endpoint code validation",
     "/api/auth/mfa/verify rejects an incorrect TOTP code",
     "Known gap as of this test cycle: no per-user TOTP secret is stored and the "
     "code is never checked — expected to FAIL until MFA is actually implemented.",
     "N/A — documents a known incomplete feature",
     "1. POST to /api/auth/mfa/verify with a deliberately wrong 6-digit code\n"
     "2. Observe response",
     "code = '000000' (wrong)",
     "Request should be rejected (expected). Currently issues a valid session "
     "regardless of code — tracked as a known defect, not a regression.",
     "", "Blocked", "High", "", "", "See conversation notes — MFA enrollment not built yet"),
]

STATUS_COLORS = {
    "Passed":       "C6EFCE",
    "Failed":       "FFC7CE",
    "Blocked":      "FFEB9C",
    "Not Executed": "D9D9D9",
}

def style_header(ws, ncols):
    header_fill = PatternFill("solid", fgColor="1F4E78")
    header_font = Font(color="FFFFFF", bold=True, size=10)
    thin = Side(style="thin", color="B7B7B7")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for c in range(1, ncols + 1):
        cell = ws.cell(row=1, column=c)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = border
    ws.freeze_panes = "A2"
    ws.row_dimensions[1].height = 30


def build_test_cases_sheet(wb):
    ws = wb.active
    ws.title = "Test Cases"
    ws.append(HEADERS)
    style_header(ws, len(HEADERS))

    thin = Side(style="thin", color="D9D9D9")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    wrap = Alignment(wrap_text=True, vertical="top")

    for row in ROWS:
        ws.append(row)

    for i, w in enumerate(COL_WIDTHS, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w

    last_row = ws.max_row
    for r in range(2, last_row + 1):
        ws.row_dimensions[r].height = 60
        for c in range(1, len(HEADERS) + 1):
            cell = ws.cell(row=r, column=c)
            cell.alignment = wrap
            cell.border = border

    # Data validation dropdowns
    status_dv = DataValidation(
        type="list",
        formula1='"Passed,Failed,Blocked,Not Executed"',
        allow_blank=True, showDropDown=False,
    )
    ws.add_data_validation(status_dv)
    status_dv.add(f"K2:K{max(last_row, 500)}")

    priority_dv = DataValidation(
        type="list",
        formula1='"Critical,High,Medium,Low"',
        allow_blank=True, showDropDown=False,
    )
    ws.add_data_validation(priority_dv)
    priority_dv.add(f"L2:L{max(last_row, 500)}")

    # Conditional formatting on Status column
    status_col = "K"
    rng = f"{status_col}2:{status_col}{max(last_row, 500)}"
    for value, color in STATUS_COLORS.items():
        fill = PatternFill("solid", fgColor=color)
        ws.conditional_formatting.add(
            rng,
            CellIsRule(operator="equal", formula=[f'"{value}"'], fill=fill),
        )

    return ws


def build_legend_sheet(wb):
    ws = wb.create_sheet("Legend & Format Guide")
    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 90

    title = ws.cell(row=1, column=1, value="Test Case Tracker — Format Guide")
    title.font = Font(bold=True, size=14, color="1F4E78")
    ws.merge_cells("A1:B1")

    rows = [
        ("Standard followed", "ISTQB / IEEE 829 style test case specification — the same shape "
         "used by TestRail, Zephyr, qTest, and most enterprise QA teams."),
        ("", ""),
        ("Column", "Meaning"),
        ("Test Case ID", "Unique, sequential, never reused (TC-001, TC-002, ...). "
         "Referenced from bug reports and traceability matrices."),
        ("Module / Feature", "Which part of the product this covers (Alerts, SOAR, Rules, Auth, ...)."),
        ("Test Scenario", "The high-level behavior under test — one scenario can have several "
         "test cases (happy path, edge case, negative case)."),
        ("Test Case Title", "Short, specific, searchable name for this exact case."),
        ("Description", "What is being verified and why it matters."),
        ("Preconditions", "State that must exist before running this case (login, data seeded, etc.)."),
        ("Test Steps / Script", "Numbered, reproducible steps — or an actual script/command block "
         "when the case is automatable (curl, API call, CLI command)."),
        ("Test Data", "Concrete inputs used for this run (specific IP, payload, username, etc.)."),
        ("Expected Result", "What should happen if the feature works correctly."),
        ("Actual Result", "What actually happened — filled in during execution, not in advance."),
        ("Status", "Passed / Failed / Blocked / Not Executed. Blocked = couldn't run "
         "(e.g. dependency broken or feature not built yet), distinct from Failed."),
        ("Priority", "Critical / High / Medium / Low — drives what gets fixed/retested first."),
        ("Executed By", "Tester name — accountability + who to ask about the result."),
        ("Execution Date", "When the case was actually run (not authored)."),
        ("Defect ID / Remarks", "Link/ID to the bug tracker entry if Failed, or free-text notes."),
        ("", ""),
        ("Workflow", "1) Write cases before testing (Status = Not Executed). "
         "2) Execute and fill Actual Result + Status + Executed By + Date as you go. "
         "3) File a defect for every Failed case and record its ID here. "
         "4) Re-run failed cases after a fix ships — same row, update Status, "
         "keep the old Actual Result in Remarks if useful for history."),
    ]
    r = 3
    for label, text in rows:
        c1 = ws.cell(row=r, column=1, value=label)
        c2 = ws.cell(row=r, column=2, value=text)
        c1.font = Font(bold=label in ("Column", "Standard followed", "Workflow"))
        c2.alignment = Alignment(wrap_text=True, vertical="top")
        c1.alignment = Alignment(vertical="top")
        ws.row_dimensions[r].height = 34 if text else 8
        r += 1


def build_summary_sheet(wb):
    ws = wb.create_sheet("Summary", 0)  # first tab
    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 14

    ws["A1"] = "NDR Test Execution Summary"
    ws["A1"].font = Font(bold=True, size=14, color="1F4E78")
    ws.merge_cells("A1:B1")

    labels = ["Total Test Cases", "Passed", "Failed", "Blocked", "Not Executed", "Pass Rate"]
    formulas = [
        '=COUNTA(\'Test Cases\'!A2:A1000)-COUNTBLANK(\'Test Cases\'!A2:A1000)',
        "=COUNTIF('Test Cases'!K2:K1000,\"Passed\")",
        "=COUNTIF('Test Cases'!K2:K1000,\"Failed\")",
        "=COUNTIF('Test Cases'!K2:K1000,\"Blocked\")",
        "=COUNTIF('Test Cases'!K2:K1000,\"Not Executed\")",
        '=IFERROR(B3/B2,"n/a")',
    ]
    r = 3
    for label, formula in zip(labels, formulas):
        ws.cell(row=r, column=1, value=label).font = Font(bold=True)
        cell = ws.cell(row=r, column=2, value=formula)
        if label == "Pass Rate":
            cell.number_format = "0.0%"
        r += 1

    ws["A10"] = "Tip: this sheet updates automatically as you fill in Status on the Test Cases tab."
    ws["A10"].font = Font(italic=True, color="808080")
    ws.merge_cells("A10:D10")


def main():
    wb = openpyxl.Workbook()
    build_test_cases_sheet(wb)
    build_legend_sheet(wb)
    build_summary_sheet(wb)
    wb.active = 0
    wb.save(OUT_PATH)
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
