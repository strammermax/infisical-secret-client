# Infisical Secret Client

Generieke, dependency-vrije Python-client voor self-hosted Infisical. De client
gebruikt Universal Auth, houdt het kortlevende access-token alleen in geheugen en
logt geen secretwaarden.

De actuele v4 Secrets API wordt gebruikt. Voor oudere self-hosted Infisical-
installaties valt de client bij een ontbrekend v4-endpoint automatisch terug op
de legacy v3-route; andere fouten worden niet gemaskeerd.

## Infisical voorbereiden

1. Maak onder Organization Settings een Machine Identity met Universal Auth.
2. Voeg die identity read-only toe aan het gewenste project.
3. Maak een Client Secret en noteer Client ID en Client Secret éénmalig.
4. Geef iedere workload uitsluitend toegang tot de benodigde secretfolders.

De bootstrapgegevens blijven lokaal op de machine, bij voorkeur in een root-only
systemd environment-bestand. Ze horen nooit in Git of een container-image.

## Installeren

```bash
python -m pip install .
```

## Configuratie

```env
INFISICAL_ADDR=http://infisical.home:8080
INFISICAL_ALLOW_HTTP=true
INFISICAL_CLIENT_ID=...
INFISICAL_CLIENT_SECRET=...
INFISICAL_PROJECT_ID=...
INFISICAL_ENVIRONMENT=prod
INFISICAL_SECRET_PATH=/Prefect
# Optioneel:
INFISICAL_SHARED_PATH=/shared
```

Gebruik voor productie bij voorkeur HTTPS met een vertrouwde interne CA. Met
`INFISICAL_CA_BUNDLE=/pad/ca.pem` kan een eigen CA worden opgegeven. HTTP vereist
bewust `INFISICAL_ALLOW_HTTP=true` omdat anders credentials leesbaar over het
netwerk reizen.

## Gebruik

```bash
# Alleen namen tonen
infisical-secrets list

# Eén waarde ophalen (wees voorzichtig met shell history/logs)
infisical-secrets get SECRET_NAME

# Een proces starten zonder secrets naar disk te schrijven
infisical-secrets run -- mijn-programma --optie

# GHCR-login; token gaat via stdin en verschijnt niet in procesargumenten
infisical-secrets docker-login --registry ghcr.io
```

Een andere app gebruikt dezelfde client met een ander app-pad, bijvoorbeeld
`/removesky`, `/LiveWeatherApp` of `/koopjesbot`. `load_bundle()` logt één keer in,
haalt de app-map en optioneel `INFISICAL_SHARED_PATH` op en levert één dictionary
terug. Zonder `INFISICAL_SHARED_PATH` wordt alleen de app-map gelezen. Bij dezelfde
key wint de waarde uit de app-map van de gedeelde standaardwaarde.

```python
from infisical_secret_client import InfisicalClient, InfisicalConfig

secrets = InfisicalClient(InfisicalConfig.from_env()).load_bundle()
# secrets bevat alle keys uit /shared + de ingestelde app-map
```

## Securitygrenzen

- De Client Secret is het eerste bootstrap-secret en moet lokaal worden beschermd.
- Een rootgebruiker kan lokale procesomgevingen en gedownloade images inspecteren.
- Maak identities read-only en beperk ze per project/folder.
- Gebruik korte TTL's en roteer Client Secrets.
- Maak nooit debuglogs van request bodies, authorization headers of secretwaarden.
