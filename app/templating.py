import datetime

from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/templates")


def _timestamp_to_date(value: int) -> str:
    return datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


templates.env.filters["timestamp_to_date"] = _timestamp_to_date
