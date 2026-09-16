class FileDatabase:
    def update_link_info(self, data):
        ids = []
        statuses = "','".join(x[3] for x in data)
        self.c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')")
        for row in self.c:
            ids.append(int(row[0]))
        return ids
