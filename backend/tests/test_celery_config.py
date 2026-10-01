"""Guards for security-relevant Celery settings (CLAUDE.md rules 1 and 7)."""

from app.core.tasks.celery_app import QUEUES, celery_app, ping


def test_only_json_is_accepted() -> None:
    conf = celery_app.conf
    assert conf.task_serializer == "json"
    assert conf.result_serializer == "json"
    assert list(conf.accept_content) == ["json"]
    assert list(conf.result_accept_content) == ["json"]


def test_time_limits_are_set() -> None:
    conf = celery_app.conf
    assert 0 < conf.task_soft_time_limit < conf.task_time_limit


def test_queues_declared() -> None:
    assert {q.name for q in celery_app.conf.task_queues} == set(QUEUES)


def test_ping_task_runs_locally() -> None:
    assert ping.apply().get() == "pong"
