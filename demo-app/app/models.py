from pydantic import BaseModel


class DocumentCreate(BaseModel):
    title: str
    body: str


class Document(DocumentCreate):
    id: int


class ConfigImport(BaseModel):
    raw_yaml: str


class RenderRequest(BaseModel):
    template: str
    context: dict = {}
