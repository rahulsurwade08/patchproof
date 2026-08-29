import { TrueForgeUI } from "@truefoundry/trueforge-ui";

export default function App() {
  return (
    <TrueForgeUI
      server={{ type: "trueforge", baseUrl: "http://[::1]:8790" }}
      agentConfig={{ mode: "SingleAgent", name: "patchproof-v2" }}
    />
  );
}
