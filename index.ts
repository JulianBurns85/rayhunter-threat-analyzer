/**
 * theme.ts — RayhunterCommand design tokens
 *
 * Dark tactical theme. High contrast. Built for reading in low light
 * at 3am while THE BOSS sleeps.
 */

export const Colors = {
  // Backgrounds
  bg:          '#0a0e13',   // deep navy-black
  bgCard:      '#111820',   // card surface
  bgCardAlt:   '#161e28',   // alternate card
  border:      '#1e2d3d',   // subtle border

  // Alert levels — match the tool's output
  triple:      '#ff3b3b',   // 🔴 TRIPLE CONFIRMATION
  dual:        '#ff8c00',   // 🟠 DUAL CONFIRMATION
  single:      '#ffd700',   // 🟡 single source
  clear:       '#00c853',   // ✅ clean / confirmed

  // Severity
  critical:    '#ff3b3b',
  high:        '#ff6b35',
  medium:      '#ffd700',
  info:        '#4fc3f7',

  // Text
  textPrimary:   '#e8edf2',
  textSecondary: '#7a9bb5',
  textMuted:     '#4a6075',
  textAccent:    '#00d4ff',

  // Status
  online:      '#00c853',
  offline:     '#ff3b3b',
  warning:     '#ffd700',

  // Tab bar
  tabActive:   '#00d4ff',
  tabInactive: '#4a6075',
};

export const Typography = {
  // Sizes
  xs:   10,
  sm:   12,
  md:   14,
  lg:   16,
  xl:   20,
  xxl:  24,
  xxxl: 32,

  // Weights
  regular: '400' as const,
  medium:  '500' as const,
  bold:    '700' as const,

  // Font family (system mono for data, system sans for UI)
  mono: 'monospace',
  sans: 'System',
};

export const Spacing = {
  xs:  4,
  sm:  8,
  md:  12,
  lg:  16,
  xl:  24,
  xxl: 32,
};

export const Radius = {
  sm:  4,
  md:  8,
  lg:  12,
  xl:  16,
  full: 999,
};

// Severity label → color
export function severityColor(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return Colors.critical;
    case 'HIGH':     return Colors.high;
    case 'MEDIUM':   return Colors.medium;
    case 'INFO':     return Colors.info;
    default:         return Colors.textMuted;
  }
}

// Corroboration level → color
export function corrobColor(nSources: number): string {
  if (nSources >= 3) return Colors.triple;
  if (nSources >= 2) return Colors.dual;
  return Colors.single;
}

// Corroboration level → label
export function corrobLabel(nSources: number): string {
  if (nSources >= 3) return '🔴 TRIPLE CONFIRMED';
  if (nSources >= 2) return '🟠 DUAL CONFIRMED';
  return '🟡 SINGLE SOURCE';
}
