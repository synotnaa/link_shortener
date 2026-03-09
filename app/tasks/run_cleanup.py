from app.main import Base, SessionLocal, cleanup_links, engine

def main() -> None:
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        result = cleanup_links(db)

    print(result.model_dump_json(indent=2))




if __name__ == '__main__':
    main()
