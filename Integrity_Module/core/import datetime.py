from datetime import datetime
from zoneinfo import ZoneInfo

local_tz = ZoneInfo("America/Costa_Rica")
now_local = datetime.now(local_tz)

print(now_local)