import aiosqlite

DB_PATH = "demo.db"
_db = None


async def init_db():
    global _db
    _db = await aiosqlite.connect(DB_PATH)
    await _db.execute(
        "CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, body TEXT)"
    )
    await _db.commit()


async def get_db():
    global _db
    if _db is None:
        await init_db()
    return _db
