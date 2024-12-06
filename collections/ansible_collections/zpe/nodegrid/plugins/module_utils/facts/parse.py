import importlib

def get_template(module=''):
    template = importlib.import_module(module)
    return template.get_template()
