from datetime import datetime


class Logger:
    def __init__(self, filename):
        self.log_file = open(filename, 'a')

    def logH1(self, message):
        log = f"XX---- {message.upper()} ----XX\n"
        self.log_file.write(log)
        print(log)

    def logH2(self, message):
        log = f"------ {message} ------\n"
        self.log_file.write(log)
        print(log)

    def logChange(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log = f"{timestamp} - {message}\n"
        self.log_file.write(log)
        print(log)

    def logHEnd(self):
        self.log_file.write("\n")
        print("\n")

    def close(self):
        self.log_file.close()