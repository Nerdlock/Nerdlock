---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Nerdlock documentation"
  text: "Documentation for Nerdlock."
  tagline: An E2EE chat application built using MLS.
  actions:
    - theme: brand
      text: Getting started
      link: /getting-started
    - theme: alt
      text: MLS Implementation
      link: /mls-implementation

features:
  - title: MLS Implementation
    details: An implementation of the MLS protocol in TypeScript.
  - title: NerdClient
    details: A TypeScript client for the Nerdlock protocol, which defines the application logic and uses the MLS protocol implementation.
  - title: Web application
    details: A web application in Vite that uses the NerdClient to render the chat interface.
  - title: Delivery Service
    details: The Delivery Service written in Bun.serve() is responsible for handling message delivery and storage.
  - title: Authentication Service
    details: The Authentication Service written in Bun.serve() and is responsible for handling user authentication and authorization.
---

