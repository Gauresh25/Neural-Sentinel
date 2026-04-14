/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          950: '#050810',
          900: '#080b14',
          800: '#0d1117',
          700: '#0f1623',
          600: '#1c2333',
          500: '#263249',
        },
        attack:  '#ff2d55',
        normal:  '#00ff88',
        warn:    '#ffd60a',
        info:    '#0a84ff',
        cyan:    '#64ffda',
        purple:  '#bf5af2',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 2.5s cubic-bezier(0.4,0,0.6,1) infinite',
        'fade-in':    'fadeIn 0.3s ease-in',
      },
      keyframes: {
        fadeIn: {
          '0%':   { opacity: '0', transform: 'translateY(-4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
