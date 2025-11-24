# Nmap Caseiro - Interface

Este projeto fornece uma interface simples em Python para ensinar e usar um "nmap caseiro" (um scanner demonstrativo).

Principais arquivos:

- `nmap_caseiro_gui.py` — interface gráfica (Tkinter). Entrada para alvo, portas, tipo de scan e caminho para script externo. Pode chamar o script externo ou usar o scanner de exemplo.
- `scanner/nmap_caseiro.py` — scanner de exemplo que simula um relatório. Útil para demonstração e testes.

Como usar (execução direta)

1. Tenha Python 3 instalado.
2. Execute a GUI:

```bash
python3 nmap_caseiro_gui.py
```

3. Preencha os campos e clique em `Run`.

Como integrar seu próprio "nmap caseiro"

- Informe o caminho do seu script Python no campo `Script externo`. A interface chamará o script com os argumentos: `python seu_script.py <target> -p <ports> -s <scan>`.
- Seu script deve aceitar esses argumentos ou você pode adaptar a chamada na GUI.

Empacotar em um executável

Instale o `pyinstaller` (opcional):

```bash
python3 -m pip install pyinstaller
```

Gerar um único executável:

```bash
pyinstaller --onefile nmap_caseiro_gui.py
```

O executável gerado ficará em `dist/nmap_caseiro_gui`.

Próximos passos sugeridos

- Adicionar validações mais robustas de entrada (hosts e portas).\
- Suporte a múltiplos scanners e formatos de saída (JSON).\
- Interface web (Flask) se preferir acessar pelo navegador.

Se quiser, eu posso: gerar testes rápidos, adicionar suporte a execução remota via SSH, ou criar um instalador/packaging automático. Diga qual opção prefere.
