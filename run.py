from core.scheduler import SecureHostScheduler


def main():

    scheduler = SecureHostScheduler(interval=5)
    scheduler.run()


if __name__ == "__main__":
    main()
