"""Start CIRA: run the local agent and open the dashboard in your browser."""
import threading
import webbrowser

import uvicorn

from agent import config
from agent.main import app

if __name__ == "__main__":
    url = f"http://127.0.0.1:{config.PORT}/"
    threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    print(f"CIRA is running at {url}  (press Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=config.PORT, log_level="warning")
