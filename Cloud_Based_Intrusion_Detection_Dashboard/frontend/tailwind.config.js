/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#080D19',
          sidebar: '#0D1526',
          card: '#121E32',
          'card-hover': '#16253e',
          accent: '#00A8FF',
          blue: '#087FE5',
          cyan: '#00C8FF',
          purple: '#8B5CF6',
          red: '#FF4560',
          orange: '#FFB020',
          green: '#00D68F',
          text: '#F1F5F9',
          muted: '#94A3B8',
          border: '#1E2D4A',
          'border-light': '#2A3F66',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
      },
      boxShadow: {
        'neon-cyan': '0 0 15px rgba(0, 200, 255, 0.25)',
        'neon-blue': '0 0 15px rgba(8, 127, 229, 0.25)',
        'neon-red': '0 0 15px rgba(255, 69, 96, 0.25)',
        'neon-green': '0 0 15px rgba(0, 214, 143, 0.25)',
        'soc-card': '0 4px 20px rgba(0, 0, 0, 0.45)',
      }
    },
  },
  plugins: [],
}
