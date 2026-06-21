import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import FloatingIcon from "./FloatingIcon";
import "./styles.css";

// One Vite bundle serves both windows; the window label decides what to render.
// The floating desktop widget runs in a separate "widget" window.
const isWidget = getCurrentWindow().label === "widget";

// The widget window is transparent; flag the document so the app chrome's opaque
// background is dropped and only the floating icon paints.
if (isWidget) document.documentElement.classList.add("widget-mode");

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>{isWidget ? <FloatingIcon /> : <App />}</React.StrictMode>
);
