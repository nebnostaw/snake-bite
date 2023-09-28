from sqlalchemy import (
    create_engine,
    Integer,
    String,
    JSON
)
from sqlalchemy.orm import (
    declarative_base
)
from sqlalchemy.schema import (
    Column,
    MetaData,
)

DB_URI = "sqlite:///sb.db"
ENGINE = create_engine(DB_URI, echo=False)
METADATA = MetaData()
BASE = declarative_base(metadata=METADATA)


class APKBackup(BASE):
    __tablename__ = "apk_backup"
    id = Column(Integer, primary_key=True, index=True)
    apk_name = Column(String(50))


class ImplicitIntent(BASE):
    __tablename__ = "implicit_intent"
    id = Column(Integer, primary_key=True, index=True)
    apk_name = Column(String(50))
    class_name = Column(String(50))
    source_method = Column(String(50))
    intent_method = Column(String(50))


class ExportedComponent(BASE):
    __tablename__ = "exported_component"
    id = Column(Integer, primary_key=True, index=True)
    component_type = Column(String(50), nullable=False)
    component_name = Column(String(50), nullable=False)
    intent_data = Column(JSON, nullable=True)

    __mapper_args__ = {
        'polymorphic_identity': 'exported_component',
        'polymorphic_on': 'component_type',
        'with_polymorphic': '*'
    }


class Service(ExportedComponent):
    rpc_methods = Column(JSON, nullable=True)

    __mapper_args__ = {
        "polymorphic_identity": "service",
        "polymorphic_load": "inline"
    }


class Receiver(ExportedComponent):
    __mapper_args__ = {
        "polymorphic_identity": "receiver",
        "polymorphic_load": "inline"
    }


class NanoWebServer(BASE):
    __tablename__ = "nano_webserver"
    id = Column(Integer, primary_key=True, index=True)
    app = Column(String(50), nullable=False)
    class_name = Column(String(50), nullable=False)
    routed_methods = Column(JSON, nullable=True)
