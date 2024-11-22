from typing import (
    Any,
    Optional,
)

class ConnPool:
    _fd: int

    def __init__(self,
                 channel,
                 callback,
                 max_capacity,
                 min_idle_time_before_gc,
                 stats_interval) -> None: ...

    def _acquire(self, id: int, dbname: str) -> None:
        ...

    def _release(self, id: int) -> None:
        ...

    def _discard(self, id: int) -> None:
        ...

    def _completed(self, id: int) -> None:
        ...

    def _failed(self, id: int, e: Any) -> None:
        ...

    def _prune(self, id: int, dbname: str) -> None:
        ...

    def _read(self) -> Any:
        ...

    def _try_read(self) -> Optional[Any]:
        ...

METRIC_ACTIVE = int
METRIC_WAITING = int
METRIC_CONNECTING = int
METRIC_RECONNECTING = int
