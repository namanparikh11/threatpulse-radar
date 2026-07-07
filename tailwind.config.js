/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Radar / cybersecurity command-center palette
        radar: {
          bg: '#070b14',
          panel: '#0d1424',
          panel2: '#101a2e',
          border: '#1c2740',
          borderStrong: '#243352',
          text: '#e2e8f0',
          muted: '#94a3b8',
          dim: '#64748b',
          accent: '#22d3ee',   // neon cyan
          accent2: '#34d399',  // neon green
          warn: '#f59e0b',
          danger: '#ef4444',
          critical: '#f43f5e',
          high: '#fb923c',
          medium: '#facc15',
          low: '#38bdf8',
        },
      },
      fontFamily: {
        sans: [
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        mono: [
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'Liberation Mono',
          'Courier New',
          'monospace',
        ],
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(34, 211, 238, 0.25), 0 0 24px -4px rgba(34, 211, 238, 0.25)',
        panel: '0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.6)',
      },
      keyframes: {
        sweep: {
          '0%':   { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        pulseDot: {
          '0%, 100%': { opacity: '1' },
          '50%':      { opacity: '0.4' },
        },
      },
      animation: {
        sweep: 'sweep 4s linear infinite',
        pulseDot: 'pulseDot 1.6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};
