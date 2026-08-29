import React from "react";
import ReactDOM from "react-dom/client";
import AppV2 from "./AppV2";
import { PasswordRecoveryRouter } from "./PasswordRecovery";
import "./styles.css";
import "./styles-v2.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <PasswordRecoveryRouter app={<AppV2 />} />
  </React.StrictMode>,
);
