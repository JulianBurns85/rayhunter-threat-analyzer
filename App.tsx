/**
 * App.tsx — RayhunterCommand navigation shell
 *
 * Bottom tab navigation:
 *   Dashboard → Analysis → CASTNET → (stack screens)
 */

import React from 'react';
import { StatusBar, View, Text, StyleSheet } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createStackNavigator } from '@react-navigation/stack';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import DashboardScreen from './src/screens/DashboardScreen';
import { Colors, Typography } from './src/theme';

const Tab   = createBottomTabNavigator();
const Stack = createStackNavigator();

// ── Placeholder screens (built out next sessions) ─────────────────── //
function PlaceholderScreen({ route }: any) {
  return (
    <View style={ph.container}>
      <Text style={ph.icon}>🔧</Text>
      <Text style={ph.title}>{route.name}</Text>
      <Text style={ph.sub}>Coming next session</Text>
    </View>
  );
}

const ph = StyleSheet.create({
  container: { flex: 1, backgroundColor: Colors.bg, alignItems: 'center', justifyContent: 'center' },
  icon:      { fontSize: 48, marginBottom: 16 },
  title:     { color: Colors.textAccent, fontSize: Typography.xl, fontFamily: 'monospace', fontWeight: '700', letterSpacing: 2 },
  sub:       { color: Colors.textMuted, fontSize: Typography.sm, fontFamily: 'monospace', marginTop: 8 },
});

// ── Main stack (Dashboard + modal screens) ────────────────────────── //
function MainStack() {
  return (
    <Stack.Navigator
      screenOptions={{
        headerStyle:      { backgroundColor: Colors.bgCard },
        headerTintColor:  Colors.textAccent,
        headerTitleStyle: { fontFamily: 'monospace', fontWeight: '700', letterSpacing: 2 },
        headerBackTitle:  'Back',
        cardStyle:        { backgroundColor: Colors.bg },
      }}
    >
      <Stack.Screen
        name="Dashboard"
        component={DashboardScreen}
        options={{ title: 'COMMAND', headerShown: false }}
      />
      <Stack.Screen name="Analysis"   component={PlaceholderScreen} options={{ title: 'ANALYSIS' }} />
      <Stack.Screen name="Attacker"   component={PlaceholderScreen} options={{ title: 'ATTACKER PROFILE' }} />
      <Stack.Screen name="CASTNET"    component={PlaceholderScreen} options={{ title: 'CASTNET' }} />
      <Stack.Screen name="Library"    component={PlaceholderScreen} options={{ title: 'ATTACK LIBRARY' }} />
      <Stack.Screen name="BugReport"  component={PlaceholderScreen} options={{ title: 'BUG REPORT' }} />
      <Stack.Screen name="Evidence"   component={PlaceholderScreen} options={{ title: 'EVIDENCE PACKAGE' }} />
    </Stack.Navigator>
  );
}

// ── Tab icon ──────────────────────────────────────────────────────── //
function TabIcon({ emoji, focused }: { emoji: string; focused: boolean }) {
  return (
    <Text style={{ fontSize: 22, opacity: focused ? 1 : 0.5 }}>{emoji}</Text>
  );
}

// ── Root navigator ────────────────────────────────────────────────── //
export default function App() {
  return (
    <SafeAreaProvider>
      <StatusBar barStyle="light-content" backgroundColor={Colors.bg} />
      <NavigationContainer>
        <Tab.Navigator
          screenOptions={{
            headerShown: false,
            tabBarStyle: {
              backgroundColor: Colors.bgCard,
              borderTopColor:  Colors.border,
              borderTopWidth:  1,
              height: 60,
              paddingBottom: 8,
            },
            tabBarActiveTintColor:   Colors.tabActive,
            tabBarInactiveTintColor: Colors.tabInactive,
            tabBarLabelStyle: {
              fontFamily: 'monospace',
              fontSize:   10,
              fontWeight: '700',
              letterSpacing: 1,
            },
          }}
        >
          <Tab.Screen
            name="Home"
            component={MainStack}
            options={{
              tabBarLabel: 'COMMAND',
              tabBarIcon: ({ focused }) => <TabIcon emoji="⚡" focused={focused} />,
            }}
          />
          <Tab.Screen
            name="AnalysisTab"
            component={PlaceholderScreen}
            options={{
              tabBarLabel: 'ANALYSIS',
              tabBarIcon: ({ focused }) => <TabIcon emoji="📊" focused={focused} />,
            }}
          />
          <Tab.Screen
            name="CASTNETTab"
            component={PlaceholderScreen}
            options={{
              tabBarLabel: 'CASTNET',
              tabBarIcon: ({ focused }) => <TabIcon emoji="🌐" focused={focused} />,
            }}
          />
          <Tab.Screen
            name="FieldTab"
            component={PlaceholderScreen}
            options={{
              tabBarLabel: 'FIELD',
              tabBarIcon: ({ focused }) => <TabIcon emoji="📡" focused={focused} />,
            }}
          />
        </Tab.Navigator>
      </NavigationContainer>
    </SafeAreaProvider>
  );
}
