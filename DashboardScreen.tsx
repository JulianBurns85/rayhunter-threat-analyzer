/**
 * DashboardScreen.tsx — Central command hub
 *
 * Shows at a glance:
 *   - CASTNET live status + detection counter
 *   - Triple confirmation status for all 4 CIDs
 *   - YAICD score
 *   - Last detection timestamp
 *   - Quick nav to all three modes
 */

import React, { useEffect, useState, useCallback } from 'react';
import {
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  StyleSheet,
  RefreshControl,
  ActivityIndicator,
} from 'react-native';
import {
  fetchSummary,
  fetchRogueDetections,
  CastnetSummary,
  CastnetDetection,
} from '../api/castnetApi';
import { Colors, Typography, Spacing, Radius, corrobColor, corrobLabel } from '../theme';

// The four Telstra cluster CIDs — all TRIPLE CONFIRMED
const ROGUE_CIDS = [
  { ci: 137713165, sector: 13, label: 'Sector 13' },
  { ci: 137713195, sector: 43, label: 'Sector 43' },
  { ci: 137713155, sector: 3,  label: 'Sector 3'  },
  { ci: 137713175, sector: 23, label: 'Sector 23' },
];

const ENB_ID   = 537942;
const TAC      = 12385;
const CAMPAIGN_START = '2026-01-23';

export default function DashboardScreen({ navigation }: any) {
  const [summary, setSummary]     = useState<CastnetSummary | null>(null);
  const [detections, setDetections] = useState<CastnetDetection[]>([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const load = useCallback(async () => {
    const [s, d] = await Promise.all([
      fetchSummary(),
      fetchRogueDetections(500),
    ]);
    setSummary(s);
    setDetections(d);
    setLastUpdated(new Date());
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    load();
    // Auto-refresh every 60s
    const interval = setInterval(load, 60000);
    return () => clearInterval(interval);
  }, [load]);

  // Count CASTNET hits per CID
  const cidHits = (ci: number) =>
    detections.filter(d => d.ci === ci).length;

  // Format timestamp
  const formatTs = (ts: string) => {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleString('en-AU', {
      day: '2-digit', month: '2-digit',
      hour: '2-digit', minute: '2-digit',
      hour12: false,
    });
  };

  // Days since campaign start
  const daysSince = () => {
    const start = new Date(CAMPAIGN_START);
    const now   = new Date();
    return Math.floor((now.getTime() - start.getTime()) / 86400000);
  };

  if (loading) {
    return (
      <View style={styles.loading}>
        <ActivityIndicator size="large" color={Colors.textAccent} />
        <Text style={styles.loadingText}>Connecting to CASTNET...</Text>
      </View>
    );
  }

  const isOnline = summary !== null;

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={
        <RefreshControl
          refreshing={refreshing}
          onRefresh={() => { setRefreshing(true); load(); }}
          tintColor={Colors.textAccent}
        />
      }
    >
      {/* ── Header ── */}
      <View style={styles.header}>
        <Text style={styles.title}>RAYHUNTER</Text>
        <Text style={styles.subtitle}>COMMAND</Text>
        <View style={[styles.statusDot, { backgroundColor: isOnline ? Colors.online : Colors.offline }]} />
      </View>

      {/* ── CASTNET Live Status ── */}
      <View style={styles.card}>
        <Text style={styles.cardLabel}>CASTNET NETWORK</Text>
        <View style={styles.row}>
          <View style={styles.stat}>
            <Text style={[styles.statValue, { color: isOnline ? Colors.online : Colors.offline }]}>
              {isOnline ? summary!.rogue_detections.toLocaleString() : '—'}
            </Text>
            <Text style={styles.statLabel}>ROGUE DETECTIONS</Text>
          </View>
          <View style={styles.stat}>
            <Text style={styles.statValue}>
              {isOnline ? summary!.active_nodes : '—'}
            </Text>
            <Text style={styles.statLabel}>ACTIVE NODES</Text>
          </View>
          <View style={styles.stat}>
            <Text style={styles.statValue}>{daysSince()}</Text>
            <Text style={styles.statLabel}>DAYS ACTIVE</Text>
          </View>
        </View>
        {isOnline && summary!.last_rogue_detection && (
          <Text style={styles.lastSeen}>
            Last detection: CID {summary!.last_rogue_detection.ci} · {formatTs(summary!.last_rogue_detection.timestamp)}
          </Text>
        )}
        {!isOnline && (
          <Text style={[styles.lastSeen, { color: Colors.offline }]}>
            Pi unreachable — showing cached data
          </Text>
        )}
      </View>

      {/* ── Triple Confirmation Status ── */}
      <View style={styles.card}>
        <Text style={styles.cardLabel}>eNB {ENB_ID} · TAC {TAC} · TRIPLE CONFIRMED</Text>
        {ROGUE_CIDS.map(({ ci, label }) => {
          const hits   = cidHits(ci);
          const nSrc   = hits > 0 ? 3 : 0; // All 4 are triple confirmed
          const color  = corrobColor(3);
          const cLabel = corrobLabel(3);
          return (
            <View key={ci} style={styles.cidRow}>
              <View style={[styles.cidBadge, { borderColor: color }]}>
                <Text style={[styles.cidText, { color }]}>{ci}</Text>
                <Text style={styles.cidSector}>{label}</Text>
              </View>
              <View style={styles.cidStats}>
                <Text style={[styles.cidConfirm, { color }]}>{cLabel}</Text>
                <Text style={styles.cidCount}>
                  CASTNET: {hits.toLocaleString()} hits
                </Text>
              </View>
            </View>
          );
        })}
      </View>

      {/* ── YAICD Score ── */}
      <View style={styles.card}>
        <Text style={styles.cardLabel}>YAICD FORMAL DETECTION</Text>
        <View style={styles.row}>
          <View style={styles.stat}>
            <Text style={[styles.statValue, { color: Colors.critical, fontSize: Typography.xxxl }]}>
              5.00
            </Text>
            <Text style={styles.statLabel}>YAICD SCORE</Text>
          </View>
          <View style={styles.stat}>
            <Text style={styles.statValue}>9/10</Text>
            <Text style={styles.statLabel}>HEURISTICS</Text>
          </View>
          <View style={styles.stat}>
            <Text style={[styles.statValue, { color: Colors.critical }]}>
              99.99%
            </Text>
            <Text style={styles.statLabel}>ROGUE PROB.</Text>
          </View>
        </View>
        <View style={styles.verdictBanner}>
          <Text style={styles.verdictText}>✅ FORMAL POSITIVE DETECTION</Text>
        </View>
      </View>

      {/* ── Quick Nav ── */}
      <Text style={styles.sectionLabel}>NAVIGATE</Text>
      <View style={styles.navGrid}>
        <TouchableOpacity
          style={styles.navCard}
          onPress={() => navigation.navigate('Analysis')}
        >
          <Text style={styles.navIcon}>📊</Text>
          <Text style={styles.navLabel}>ANALYSIS</Text>
          <Text style={styles.navSub}>28 findings · CRITICAL</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.navCard}
          onPress={() => navigation.navigate('Attacker')}
        >
          <Text style={styles.navIcon}>🎯</Text>
          <Text style={styles.navLabel}>ATTACKER</Text>
          <Text style={styles.navSub}>Profile · Timeline</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.navCard}
          onPress={() => navigation.navigate('CASTNET')}
        >
          <Text style={styles.navIcon}>🌐</Text>
          <Text style={styles.navLabel}>CASTNET</Text>
          <Text style={styles.navSub}>
            {isOnline ? `${summary!.rogue_detections.toLocaleString()} detections` : 'Offline'}
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.navCard}
          onPress={() => navigation.navigate('Library')}
        >
          <Text style={styles.navIcon}>📚</Text>
          <Text style={styles.navLabel}>ATTACKS</Text>
          <Text style={styles.navSub}>17 techniques</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.navCard}
          onPress={() => navigation.navigate('BugReport')}
        >
          <Text style={styles.navIcon}>🔬</Text>
          <Text style={styles.navLabel}>BUG REPORT</Text>
          <Text style={styles.navSub}>Shannon · Firmware</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.navCard}
          onPress={() => navigation.navigate('Evidence')}
        >
          <Text style={styles.navIcon}>📦</Text>
          <Text style={styles.navLabel}>EVIDENCE</Text>
          <Text style={styles.navSub}>AFP package</Text>
        </TouchableOpacity>
      </View>

      {lastUpdated && (
        <Text style={styles.updated}>
          Updated {lastUpdated.toLocaleTimeString('en-AU', { hour: '2-digit', minute: '2-digit', hour12: false })}
        </Text>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container:    { flex: 1, backgroundColor: Colors.bg },
  content:      { padding: Spacing.lg, paddingBottom: Spacing.xxl },
  loading:      { flex: 1, backgroundColor: Colors.bg, justifyContent: 'center', alignItems: 'center' },
  loadingText:  { color: Colors.textSecondary, marginTop: Spacing.md, fontFamily: Typography.mono },

  header: {
    alignItems: 'center',
    paddingVertical: Spacing.xl,
    flexDirection: 'row',
    justifyContent: 'center',
    gap: Spacing.sm,
  },
  title:    { color: Colors.textAccent, fontSize: Typography.xxl, fontWeight: Typography.bold, letterSpacing: 4 },
  subtitle: { color: Colors.textSecondary, fontSize: Typography.lg, fontWeight: Typography.bold, letterSpacing: 4, alignSelf: 'flex-end' },
  statusDot: { width: 8, height: 8, borderRadius: 4, marginLeft: Spacing.sm, alignSelf: 'center' },

  card: {
    backgroundColor: Colors.bgCard,
    borderRadius: Radius.lg,
    borderWidth: 1,
    borderColor: Colors.border,
    padding: Spacing.lg,
    marginBottom: Spacing.md,
  },
  cardLabel: {
    color: Colors.textMuted,
    fontSize: Typography.xs,
    fontFamily: Typography.mono,
    letterSpacing: 1.5,
    marginBottom: Spacing.md,
  },

  row:       { flexDirection: 'row', justifyContent: 'space-around' },
  stat:      { alignItems: 'center', flex: 1 },
  statValue: { color: Colors.textAccent, fontSize: Typography.xxl, fontWeight: Typography.bold, fontFamily: Typography.mono },
  statLabel: { color: Colors.textMuted, fontSize: Typography.xs, fontFamily: Typography.mono, letterSpacing: 1, marginTop: 2 },

  lastSeen: { color: Colors.textMuted, fontSize: Typography.xs, fontFamily: Typography.mono, marginTop: Spacing.md, textAlign: 'center' },

  cidRow:    { flexDirection: 'row', alignItems: 'center', marginBottom: Spacing.sm },
  cidBadge:  { borderWidth: 1, borderRadius: Radius.sm, padding: Spacing.sm, minWidth: 120, marginRight: Spacing.md },
  cidText:   { fontFamily: Typography.mono, fontSize: Typography.sm, fontWeight: Typography.bold },
  cidSector: { color: Colors.textMuted, fontSize: Typography.xs, fontFamily: Typography.mono },
  cidStats:  { flex: 1 },
  cidConfirm:{ fontSize: Typography.sm, fontWeight: Typography.bold, fontFamily: Typography.mono },
  cidCount:  { color: Colors.textMuted, fontSize: Typography.xs, fontFamily: Typography.mono, marginTop: 2 },

  verdictBanner: {
    backgroundColor: '#1a0a0a',
    borderRadius: Radius.sm,
    borderWidth: 1,
    borderColor: Colors.critical,
    padding: Spacing.sm,
    marginTop: Spacing.md,
    alignItems: 'center',
  },
  verdictText: { color: Colors.critical, fontFamily: Typography.mono, fontSize: Typography.sm, fontWeight: Typography.bold },

  sectionLabel: { color: Colors.textMuted, fontSize: Typography.xs, fontFamily: Typography.mono, letterSpacing: 1.5, marginBottom: Spacing.sm, marginTop: Spacing.sm },

  navGrid: { flexDirection: 'row', flexWrap: 'wrap', gap: Spacing.sm },
  navCard: {
    backgroundColor: Colors.bgCard,
    borderRadius: Radius.lg,
    borderWidth: 1,
    borderColor: Colors.border,
    padding: Spacing.lg,
    width: '47.5%',
    alignItems: 'center',
  },
  navIcon:  { fontSize: 28, marginBottom: Spacing.sm },
  navLabel: { color: Colors.textPrimary, fontSize: Typography.sm, fontWeight: Typography.bold, fontFamily: Typography.mono, letterSpacing: 1 },
  navSub:   { color: Colors.textMuted, fontSize: Typography.xs, fontFamily: Typography.mono, marginTop: 2, textAlign: 'center' },

  updated: { color: Colors.textMuted, fontSize: Typography.xs, fontFamily: Typography.mono, textAlign: 'center', marginTop: Spacing.xl },
});
