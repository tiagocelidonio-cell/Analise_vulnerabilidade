import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { loadBranding } from "./branding.js";
import "./styles.css";

loadBranding();

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
