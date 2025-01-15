from celery import shared_task
from django.utils.module_loading import import_string

from intel_owl.tasks import FailureLoggedTask


@shared_task(base=FailureLoggedTask, soft_time_limit=300)
def execute_engine_module(job_pk:int, path:str):
    from api_app.models import Job
    from api_app.engines_manager.classes import EngineModule

    job = Job.objects.get(pk=job_pk)
    obj: EngineModule = import_string(path)(job)
    module_result = obj.run()
    job.data_model.merge(module_result, append=False)
