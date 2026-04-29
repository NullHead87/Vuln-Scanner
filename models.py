from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from database import Base

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="completed")
    headers_score = Column(Integer, default=0)
    tls_score = Column(Integer, default=0)
    dns_score = Column(Integer, default=0)
    cookies_score = Column(Integer, default=0)
    overall_score = Column(Integer, default=0)
    headers_detail = Column(Text, nullable=True)
    tls_detail = Column(Text, nullable=True)
    redirects_detail = Column(Text, nullable=True)
    dns_detail = Column(Text, nullable=True)
    methods_detail = Column(Text, nullable=True)
    cookies_detail = Column(Text, nullable=True)
    ports_detail = Column(Text, nullable=True)
    subdomains_detail = Column(Text, nullable=True)
    info_detail = Column(Text, nullable=True)