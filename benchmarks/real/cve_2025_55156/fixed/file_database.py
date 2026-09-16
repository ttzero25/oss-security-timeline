class FileDatabase:
    def update_link_info(self, data):
        urls = [x[3] for x in data]
        placeholders = ",".join("?" * len(urls))
        self.c.execute(
            f"SELECT id FROM links WHERE url IN ({placeholders})", urls
        )
        return [int(row[0]) for row in self.c.fetchall()]
