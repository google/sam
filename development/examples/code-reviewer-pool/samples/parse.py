# Sample file with intentional issues for the reviewer pool to find.
def parse_range(spec):
    start, end = spec.split("-")
    return list(range(int(start), int(end)))


def load(path):
    f = open(path)
    data = f.read()
    return [parse_range(line) for line in data.split(",")]
