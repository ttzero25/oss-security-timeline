import requests


class App:
    def get(self, _path):
        return lambda function: function


app = App()


@app.get("/fetch")
def fetch(url):
    return requests.get(url)
