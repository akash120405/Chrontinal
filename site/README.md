# Chrontinal SOC public frontend

This folder is a standalone static landing page for GitHub Pages. It uses local HTML, CSS, and JavaScript with system fonts. It does not require a build step or any external asset service.

The interactive dashboard and APIs must run on a separate host. GitHub Pages can serve this public frontend, but it cannot run the Next.js server or keep the Groq API key private.

## Connect the live dashboard

After deploying the dashboard, edit `config.js`:

```js
window.CHRONTINAL_APP_URL = "https://your-dashboard.example.com";
```

Use the dashboard's base HTTPS URL, with no trailing route. The public page adds routes such as `/dashboard` and `/alerts` to that URL. Until it is set, dashboard buttons lead to the explanatory section at the bottom of the page.

Never put an API key in this folder or in `config.js`. Configure the key only in the private environment of the live dashboard service.
