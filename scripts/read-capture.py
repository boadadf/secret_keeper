"""View existing JSONL payload captures as readable text, entirely locally."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
spec=importlib.util.spec_from_file_location("capture_formatter",Path(__file__).resolve().parents[1]/"src/secret_keeper/readable_capture.py")
fmt=importlib.util.module_from_spec(spec);spec.loader.exec_module(fmt)

def main():
    parser=argparse.ArgumentParser(description="Read sensitive outbound JSONL captures locally. Does not send data anywhere.")
    parser.add_argument("file",type=Path)
    parser.add_argument("--decision",choices=["ALLOW","BLOCK"])
    parser.add_argument("--transport",choices=["http","websocket"])
    parser.add_argument("--output",type=Path,help="New local text file; refuses overwrite")
    parser.add_argument("--width",type=int,default=100)
    args=parser.parse_args()
    destination=None;count=0
    try:
        if args.output:destination=args.output.open("x",encoding="utf-8")
        target=destination or sys.stdout
        with args.file.open(encoding="utf-8") as source:
            number=0
            while True:
                line=source.readline(33554433)
                if not line:break
                number+=1
                if len(line)>33554432:raise ValueError("record exceeds viewer's 32 MiB line limit")
                if not line.strip():continue
                try:record=json.loads(line)
                except (ValueError,RecursionError):raise ValueError("invalid/incomplete JSONL record "+str(number))
                if not isinstance(record,dict):raise ValueError("record must be object")
                if args.decision and record.get("final_decision")!=args.decision:continue
                if args.transport and record.get("transport")!=args.transport:continue
                target.write(fmt.readable(record,width=args.width));count+=1
        print("Displayed "+str(count)+" matching capture records.",file=sys.stderr)
        return 0
    except (OSError,ValueError,TypeError,RecursionError) as error:
        print("ERROR: "+str(error),file=sys.stderr);return 1
    finally:
        if destination:destination.close()

if __name__=="__main__":
    if hasattr(sys.stdout,"reconfigure"):sys.stdout.reconfigure(errors="replace")
    sys.exit(main())
