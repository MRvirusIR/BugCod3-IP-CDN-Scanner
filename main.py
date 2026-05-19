from core.engine import ScanEngine

if __name__ == "__main__":

    engine = ScanEngine(
        input_file="data/targets.txt"
    )

    engine.run()
