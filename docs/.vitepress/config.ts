import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "Nerdlock MLS documentation",
  description: "Documentation for the underlying MLS implementation that powers Nerdlock.",
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Getting Started', link: '/gs/prerequisites' },
      { text: 'Client', link: '/client/intro' },
      { text: 'DS', link: '/ds/intro' },
      { text: 'AS', link: '/as/intro' },
    ],

    sidebar: [
      {
        text: 'Getting started',
        items: [
          { text: 'Prerequisites', link: '/gs/prerequisites' },
          { text: 'Setup', link: '/gs/setup' },
          { text: 'Building', link: '/gs/building' },
        ]
      },
      {
        text: 'Client',
        items: [
          { text: 'Introduction', link: '/client/intro' },
          { text: 'Usage', link: '/client/usage' },
          { text: 'API Examples', link: '/client/api-examples' },
        ]
      },

    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/Nerdlock/Nerdlock' }
    ]
  }
})
