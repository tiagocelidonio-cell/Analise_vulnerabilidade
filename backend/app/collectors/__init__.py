from app.collectors.port_scan import PortScanCollector

# Registro de coletores disponiveis. Adicione novos aqui.
COLLECTORS = {
    "port_scan": PortScanCollector(),
}
