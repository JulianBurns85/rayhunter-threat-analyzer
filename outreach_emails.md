# Outreach emails — rayhunter-threat-analyzer v4.4

---

## EMAIL 1: GrapheneOS
**To:** discuss.grapheneos.org (forum post) or Matrix: #grapheneos:grapheneos.org
**Subject:** Open-source tool: firmware-layer IMSI catcher detection via Shannon IMS logs — works on every supported GrapheneOS device

Hi GrapheneOS community,

I want to flag a forensic detection capability I've built that is directly relevant to every device your OS supports.

**The tool**

rayhunter-threat-analyzer is an open-source cellular surveillance detection tool that processes Rayhunter capture files across 35+ heuristics, scored against the YAICD framework. It's MIT licensed and available at github.com/JulianBurns85/rayhunter-threat-analyzer.

**The relevant new capability**

In v4.4 I've added a Shannon IMS log parser. It reads standard Android bug reports and extracts `RILC_UNSOL_IMS_SUPPORT_SERVICE` events from `com.shannon.imsservice` — Samsung's proprietary IMS stack running at firmware level. These events record the Cell ID, TAC, and PLMN of every cell the modem registers to, independently of any passive capture tool.

The parser cross-references those events against a known rogue CID list and produces a finding flagged as firmware-layer independent corroboration — a separate evidence class from RF capture data entirely.

**Why this matters for your users specifically**

Every device currently supported by GrapheneOS — Pixel 6 through Pixel 10 across all variants — ships with a Samsung Exynos modem running the Shannon stack. This means every GrapheneOS user can generate this forensic evidence from a standard Android bug report: Settings → About phone → Bug report (Full).

GrapheneOS users are exactly the population most likely to be actively targeted by IMSI catchers. Journalists, lawyers, activists, security researchers. They are also the population most likely to generate a proper bug report and understand what to do with the output.

**The independence argument**

The significance isn't just detection — it's the independence property. If Rayhunter detects a rogue cell, and separately the phone's own modem firmware independently logged connecting to the same CID, those are two different evidence classes. That combination directly counters the "equipment malfunction" or "testing signal" argument that investigators and carriers use to dismiss single-source detections.

The Shannon log is unsolicited hardware-layer output. It cannot be influenced by Rayhunter or any other user-space tool.

**Confirmed in real-world use**

This isn't theoretical. The parser was built after discovering that a bug report from my own Pixel 9 Pro Fold running GrapheneOS contained exactly these log entries — `RILC_UNSOL_IMS_SUPPORT_SERVICE` events timestamped during a confirmed rogue cell detection event, logging the same CID independently of the Rayhunter capture happening simultaneously on the same device.

I'm not claiming this is a universal solution. I'm saying it exists, it works on every device you support, and the people who need it should know it's there.

**One caveat worth noting**

Pixel 11 series (Tensor G6) may move to a MediaTek modem — applicability to that generation is unconfirmed pending hardware teardown data.

Repository: github.com/JulianBurns85/rayhunter-threat-analyzer
Happy to answer technical questions or provide raw log data for independent verification.

Julian Burns
Victoria, Australia
GitHub: JulianBurns85

---

## EMAIL 2: EFF / Hayley Pedersen
**To:** Hayley Pedersen, EFF (existing contact)
**Subject:** Update — Shannon IMS parser built, works on every GrapheneOS device, wanted you to know

Hi Hayley,

Quick update on the investigation and a new tool capability I think is worth your attention.

You'll recall I was invited to contribute to the Atlas of Surveillance project earlier this year. The investigation has continued progressing — the corpus is now sealed at 325,000+ events across 18 months with formal complaints lodged with ACMA, Victoria Police, and the AFP. That side of things is now in the hands of the relevant agencies.

What I wanted to flag is something that came out of the investigation that has broader relevance beyond my own case.

**The Shannon IMS parser**

While analysing an Android bug report from my Pixel 9 Pro Fold running GrapheneOS, I discovered that Samsung's Shannon baseband modem independently logged connection to a confirmed rogue cell — at the firmware layer, via `com.shannon.imsservice`, completely independent of the Rayhunter passive capture running on the same device simultaneously.

I've built a parser for this into rayhunter-threat-analyzer v4.4. It reads standard Android bug reports, extracts `RILC_UNSOL_IMS_SUPPORT_SERVICE` events, cross-references against a known rogue CID list, and produces a forensic finding flagged as firmware-layer independent corroboration.

**Why this matters beyond my investigation**

Every Google Pixel from Pixel 6 through Pixel 10 uses a Samsung Exynos modem running this Shannon stack. That means every GrapheneOS device currently in existence is covered. More broadly, combined with the existing QMDL pipeline for Qualcomm devices, the tool now achieves independent corroboration capability across approximately 95% of the Android ecosystem.

The independence property is the key thing. A phone's own baseband firmware logging a rogue CID is a fundamentally different evidence class from a passive capture tool detecting the same cell. When both confirm the same event, the "equipment error" or "legitimate testing" dismissal doesn't survive.

This is the first open-source IMSI catcher detection tool I'm aware of that uses firmware-layer baseband logs as an independent corroboration layer. If that's inaccurate I'd welcome the correction — but I've checked Rayhunter, AIMSICD, and SnoopSnitch and none of them do this.

**The repo**

github.com/JulianBurns85/rayhunter-threat-analyzer — MIT licensed, documented, Shannon IMS parser in the detectors folder.

I thought this was worth flagging to you directly given the Atlas of Surveillance connection and EFF's work on IMSI catcher documentation. Happy to discuss further or provide the raw bug report data for independent verification.

Best regards,
Julian Burns
Victoria, Australia
[email on request]
GitHub: JulianBurns85

---

## EMAIL 3: ABC Investigations
**To:** abc.investigations@abc.net.au
**Subject:** Follow-up: civilian IMSI catcher investigation — new forensic tool with broad implications

Hi ABC Investigations team,

I've been in contact previously regarding my 18-month civilian investigation into unlawful IMSI catcher operation near my home in Victoria. I wanted to flag a development that I think has significance beyond my own case.

**Quick background**

Over 18 months I built an open-source cellular surveillance detection tool — rayhunter-threat-analyzer — to document what I believe to be unlawful IMSI catcher operation near my property. The investigation produced a corpus of 325,000+ cellular events, formal complaints with ACMA, Victoria Police, and the AFP, and a sealed forensic record with chain-of-custody documentation. The matter is currently with the AFP.

**What's new and why it's relevant to a broader story**

In the course of that investigation, I discovered something I don't believe has been documented publicly before: standard Android bug reports contain firmware-layer logs from the phone's own baseband modem that independently record which cell towers the phone connected to — including rogue ones.

Specifically, Samsung's Shannon modem — which powers every Google Pixel from the Pixel 6 through Pixel 10 — logs `RILC_UNSOL_IMS_SUPPORT_SERVICE` events at the firmware level. These events record the Cell ID and network details of every cell the phone registers to, before any user application is involved.

I've built a parser for this and incorporated it into my open-source tool. It means that anyone who generates a standard Android bug report while their phone is connected to a rogue cell has firmware-level evidence of that connection — independent of any third-party detection tool.

**The broader significance**

Every device running GrapheneOS — the privacy-focused Android operating system used by journalists, lawyers, activists, and security researchers — uses one of these modems. Combined with the existing detection pipeline, the tool now has independent corroboration capability across approximately 95% of Android devices.

The story here isn't just my investigation. It's that the phones being surveilled contain evidence of that surveillance in their own firmware logs — and until now, nobody knew to look there.

**What I can offer**

- The open-source tool and full technical documentation
- 18 months of corpus data documenting real-world IMSI catcher behaviour including regulatory response patterns
- The Android bug report containing the firmware-level evidence (with personal details redacted as appropriate)
- Context on the formal complaint process across ACMA, TIO, Victoria Police, and AFP

I'm conscious of not wanting to prejudice the AFP investigation and am happy to discuss what can and can't be discussed at this stage.

Repository: github.com/JulianBurns85/rayhunter-threat-analyzer

Best regards,
Julian Burns
Victoria, Australia
[email on request]
GitHub: JulianBurns85
