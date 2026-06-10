with open('detectors/operational_profile_synthesiser.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add set_findings method and findings-based counting
old = '''    def analyze(self, events: List[Dict]) -> List[Dict]:
        # This detector synthesises from the event corpus
        # The full finding synthesis happens in post_analyze()
        # Here we produce a finding from what we can extract directly
        findings = []'''

new = '''    def set_findings(self, findings: List[Dict]) -> None:
        """Receive accumulated findings from all other detectors."""
        self._all_findings = findings

    def _count_from_findings(self, keyword: str) -> int:
        """Pull confirmed counts from existing findings by keyword."""
        if not hasattr(self, '_all_findings'):
            return 0
        for f in self._all_findings:
            title = str(f.get('title', '')).lower()
            desc = str(f.get('description', '')).lower()
            if keyword in title or keyword in desc:
                # Extract number from description if present
                import re
                nums = re.findall(r'(\d+)\s*(?:confirmed|event|injection|harvest|tracking)', desc)
                if nums:
                    return int(nums[0])
        return 0

    def analyze(self, events: List[Dict]) -> List[Dict]:
        findings = []'''

content = content.replace(old, new)

# Replace the counting section with findings-based counts
old2 = '''        # Count key techniques
        handovers  = sum(1 for e in events
                        if "mobilitycontrolinfo" in
                        str(e.get("message_type","")).lower() or
                        "rrcconnectionreconfiguration" in
                        str(e.get("message_type","")).lower())
        imsi_events= sum(1 for e in events
                        if "identityrequest" in
                        str(e.get("message_type","")).lower())
        prose      = sum(1 for e in events
                        if "reportproximityconfig" in
                        str(e.get("message_type","")).lower() or
                        "prose" in str(e.get("message_type","")).lower())
        releases   = sum(1 for e in events
                        if "rrcconnectionrelease" in
                        str(e.get("message_type","")).lower())'''

new2 = '''        # Pull confirmed counts from accumulated findings
        # (events list may be empty if not stored in JSON)
        import re as _re

        def _extract_count(keyword, fallback_keywords=None):
            if not hasattr(self, '_all_findings'):
                return 0
            for f in self._all_findings:
                title = str(f.get('title', '')).lower()
                desc = str(f.get('description', '')).lower()
                search_terms = [keyword] + (fallback_keywords or [])
                if any(t in title for t in search_terms):
                    nums = _re.findall(r'(\d[\d,]*)\s*(?:injected|confirmed|event|harvest)', desc)
                    if nums:
                        return int(nums[0].replace(',', ''))
            return 0

        handovers   = _extract_count('handover inject', ['mobilitycontrolinfo'])
        imsi_events = _extract_count('imsi harvest', ['identity request', 'imsi catcher'])
        prose       = _extract_count('prose', ['proximity tracking', 'reportproximityconfig'])

        # releases still from events (fast count, usually available)
        releases = sum(1 for e in events
                      if "rrcconnectionrelease" in
                      str(e.get("message_type","")).lower())

        # fallback: pull from handover finding directly
        if handovers == 0 and hasattr(self, '_all_findings'):
            for f in self._all_findings:
                title = str(f.get('title', '')).lower()
                if 'handover' in title and 'inject' in title:
                    nums = _re.findall(r'(\d+)\s*rrc', str(f.get('description','')).lower())
                    if not nums:
                        nums = _re.findall(r'(\d+)\s*message', str(f.get('description','')).lower())
                    if nums:
                        handovers = int(nums[0])
                    break
        if imsi_events == 0 and hasattr(self, '_all_findings'):
            for f in self._all_findings:
                title = str(f.get('title', '')).lower()
                if 'imsi' in title and ('harvest' in title or 'identity' in title):
                    nums = _re.findall(r'(\d+)\s*imsi', str(f.get('description','')).lower())
                    if not nums:
                        nums = _re.findall(r'(\d+)\s*identity', str(f.get('description','')).lower())
                    if nums:
                        imsi_events = int(nums[0])
                    break
        if prose == 0 and hasattr(self, '_all_findings'):
            for f in self._all_findings:
                title = str(f.get('title', '')).lower()
                if 'prose' in title or 'proximity' in title:
                    nums = _re.findall(r'(\d+)\s*rrc', str(f.get('description','')).lower())
                    if nums:
                        prose = int(nums[0])
                    break'''

content = content.replace(old2, new2)

with open('detectors/operational_profile_synthesiser.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("operational_profile_synthesiser.py patched")
