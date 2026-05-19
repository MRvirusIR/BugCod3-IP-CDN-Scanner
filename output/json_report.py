import json
from datetime import datetime

def save_json(data):

    with open("report.json", "w") as f:

        json.dump({
            "time": str(datetime.now()),
            "count": len(data),
            "results": data
        }, f, indent=4, default=str)
