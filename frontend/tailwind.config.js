/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      colors: {
        background: '#000000',
        'background-alt': '#050505',
        surface: '#0A0A0A',
        'surface-elevated': '#121212',
        'surface-highlight': '#1A180C',
        border: '#26200A',
        'border-subtle': '#181404',
        'border-active': '#FFD400',
        primary: {
          DEFAULT: '#FFD400',
          hover: '#FFE033',
          dark: '#B39200',
        },
        accent: {
          yellow: '#FFD400',
          gold: '#C7A200',
        },
        neutral: {
          text: '#FFF8DB',
          secondary: '#C7B988',
          muted: '#7A7256',
        },
        critical: {
          DEFAULT: '#FF4444',
          bg: '#2B0B0B',
          border: '#5C1414',
          text: '#FFA3A3',
        },
        high: {
          DEFAULT: '#FF8800',
          bg: '#2E1400',
          border: '#5C2800',
          text: '#FFBA66',
        },
        medium: {
          DEFAULT: '#FFD400',
          bg: '#292200',
          border: '#5C4D00',
          text: '#FFE466',
        },
        low: {
          DEFAULT: '#84CC16',
          bg: '#102404',
          border: '#254E0A',
          text: '#B1E868',
        },
        info: {
          DEFAULT: '#858E96',
          bg: '#14171A',
          border: '#2B3036',
          text: '#BDC5CC',
        },
      },
    },
  },
  plugins: [],
}
