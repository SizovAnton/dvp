from syslog_handling.load_file import load_csv_file

art_log = "/home/ash/Проекти/dvp/log.csv"
siem_log = "/home/ash/Проекти/dvp/1790973286_194.csv"

def main():
    try:
        atomic = load_csv_file(art_log)

    except Exception as e:
        print(f"Error: {e}")

    try:
        siem = load_csv_file(siem_log)
        for item in siem:
           
            return atomic
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()