"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

const mongodb = require('mongodb');

const Collection = mongodb.Collection;

class MongoCollection {
  constructor(mongoCollection) {
    this._mongoCollection = mongoCollection;
  } // Does a find with "smart indexing".
  // Currently this just means, if it needs a geoindex and there is
  // none, then build the geoindex.
  // This could be improved a lot but it's not clear if that's a good
  // idea. Or even if this behavior is a good idea.


  find(query, {
    skip,
    limit,
    sort,
    keys,
    maxTimeMS,
    readPreference
  } = {}) {
    // Support for Full Text Search - $text
    if (keys && keys.$score) {
      delete keys.$score;
      keys.score = {
        $meta: 'textScore'
      };
    }

    return this._rawFind(query, {
      skip,
      limit,
      sort,
      keys,
      maxTimeMS,
      readPreference
    }).catch(error => {
      // Check for "no geoindex" error
      if (error.code != 17007 && !error.message.match(/unable to find index for .geoNear/)) {
        throw error;
      } // Figure out what key needs an index


      const key = error.message.match(/field=([A-Za-z_0-9]+) /)[1];

      if (!key) {
        throw error;
      }

      var index = {};
      index[key] = '2d';
      return this._mongoCollection.createIndex(index) // Retry, but just once.
      .then(() => this._rawFind(query, {
        skip,
        limit,
        sort,
        keys,
        maxTimeMS,
        readPreference
      }));
    });
  }

  _rawFind(query, {
    skip,
    limit,
    sort,
    keys,
    maxTimeMS,
    readPreference
  } = {}) {
    let findOperation = this._mongoCollection.find(query, {
      skip,
      limit,
      sort,
      readPreference
    });

    if (keys) {
      findOperation = findOperation.project(keys);
    }

    if (maxTimeMS) {
      findOperation = findOperation.maxTimeMS(maxTimeMS);
    }

    return findOperation.toArray();
  }

  count(query, {
    skip,
    limit,
    sort,
    maxTimeMS,
    readPreference
  } = {}) {
    // If query is empty, then use estimatedDocumentCount instead.
    // This is due to countDocuments performing a scan,
    // which greatly increases execution time when being run on large collections.
    // See https://github.com/Automattic/mongoose/issues/6713 for more info regarding this problem.
    if (typeof query !== 'object' || !Object.keys(query).length) {
      return this._mongoCollection.estimatedDocumentCount({
        maxTimeMS
      });
    }

    const countOperation = this._mongoCollection.countDocuments(query, {
      skip,
      limit,
      sort,
      maxTimeMS,
      readPreference
    });

    return countOperation;
  }

  distinct(field, query) {
    return this._mongoCollection.distinct(field, query);
  }

  aggregate(pipeline, {
    maxTimeMS,
    readPreference
  } = {}) {
    return this._mongoCollection.aggregate(pipeline, {
      maxTimeMS,
      readPreference
    }).toArray();
  }

  insertOne(object, session) {
    return this._mongoCollection.insertOne(object, {
      session
    });
  } // Atomically updates data in the database for a single (first) object that matched the query
  // If there is nothing that matches the query - does insert
  // Postgres Note: `INSERT ... ON CONFLICT UPDATE` that is available since 9.5.


  upsertOne(query, update, session) {
    return this._mongoCollection.updateOne(query, update, {
      upsert: true,
      session
    });
  }

  updateOne(query, update) {
    return this._mongoCollection.updateOne(query, update);
  }

  updateMany(query, update, session) {
    return this._mongoCollection.updateMany(query, update, {
      session
    });
  }

  deleteMany(query, session) {
    return this._mongoCollection.deleteMany(query, {
      session
    });
  }

  _ensureSparseUniqueIndexInBackground(indexRequest) {
    return new Promise((resolve, reject) => {
      this._mongoCollection.createIndex(indexRequest, {
        unique: true,
        background: true,
        sparse: true
      }, error => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  }

  drop() {
    return this._mongoCollection.drop();
  }

}

exports.default = MongoCollection;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9BZGFwdGVycy9TdG9yYWdlL01vbmdvL01vbmdvQ29sbGVjdGlvbi5qcyJdLCJuYW1lcyI6WyJtb25nb2RiIiwicmVxdWlyZSIsIkNvbGxlY3Rpb24iLCJNb25nb0NvbGxlY3Rpb24iLCJjb25zdHJ1Y3RvciIsIm1vbmdvQ29sbGVjdGlvbiIsIl9tb25nb0NvbGxlY3Rpb24iLCJmaW5kIiwicXVlcnkiLCJza2lwIiwibGltaXQiLCJzb3J0Iiwia2V5cyIsIm1heFRpbWVNUyIsInJlYWRQcmVmZXJlbmNlIiwiJHNjb3JlIiwic2NvcmUiLCIkbWV0YSIsIl9yYXdGaW5kIiwiY2F0Y2giLCJlcnJvciIsImNvZGUiLCJtZXNzYWdlIiwibWF0Y2giLCJrZXkiLCJpbmRleCIsImNyZWF0ZUluZGV4IiwidGhlbiIsImZpbmRPcGVyYXRpb24iLCJwcm9qZWN0IiwidG9BcnJheSIsImNvdW50IiwiT2JqZWN0IiwibGVuZ3RoIiwiZXN0aW1hdGVkRG9jdW1lbnRDb3VudCIsImNvdW50T3BlcmF0aW9uIiwiY291bnREb2N1bWVudHMiLCJkaXN0aW5jdCIsImZpZWxkIiwiYWdncmVnYXRlIiwicGlwZWxpbmUiLCJpbnNlcnRPbmUiLCJvYmplY3QiLCJzZXNzaW9uIiwidXBzZXJ0T25lIiwidXBkYXRlIiwidXBkYXRlT25lIiwidXBzZXJ0IiwidXBkYXRlTWFueSIsImRlbGV0ZU1hbnkiLCJfZW5zdXJlU3BhcnNlVW5pcXVlSW5kZXhJbkJhY2tncm91bmQiLCJpbmRleFJlcXVlc3QiLCJQcm9taXNlIiwicmVzb2x2ZSIsInJlamVjdCIsInVuaXF1ZSIsImJhY2tncm91bmQiLCJzcGFyc2UiLCJkcm9wIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUEsTUFBTUEsT0FBTyxHQUFHQyxPQUFPLENBQUMsU0FBRCxDQUF2Qjs7QUFDQSxNQUFNQyxVQUFVLEdBQUdGLE9BQU8sQ0FBQ0UsVUFBM0I7O0FBRWUsTUFBTUMsZUFBTixDQUFzQjtBQUduQ0MsRUFB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QUk7QUFDUCxZQUFJQSxLQUFKLEVBQVc7QUFDVGtDLFVBQUFBLE1BQU0sQ0FBQ2xDLEtBQUQsQ0FBTjtBQUNELFNBRkQsTUFFTztBQUNMaUMsVUFBQUEsT0FBTztBQUNSO0FBQ0YsT0FUSDtBQVdELEtBWk0sQ0FBUDtBQWFEOztBQUVESyxFQUFBQSxJQUFJLEdBQUc7QUFDTCxXQUFPLEtBQUtwRCxnQkFBTCxDQUFzQm9ELElBQXRCLEVBQVA7QUFDRDs7QUExSmtDIiwic291cmNlc0NvbnRlbnQiOlsiY29uc3QgbW9uZ29kYiA9IHJlcXVpcmUoJ21vbmdvZGInKTtcbmNvbnN0IENvbGxlY3Rpb24gPSBtb25nb2RiLkNvbGxlY3Rpb247XG5cbmV4cG9ydCBkZWZhdWx0IGNsYXNzIE1vbmdvQ29sbGVjdGlvbiB7XG4gIF9tb25nb0NvbGxlY3Rpb246IENvbGxlY3Rpb247XG5cbiAgY29uc3RydWN0b3IobW9uZ29Db2xsZWN0aW9uOiBDb2xsZWN0aW9uKSB7XG4gICAgdGhpcy5fbW9uZ29Db2xsZWN0aW9uID0gbW9uZ29Db2xsZWN0aW9uO1xuICB9XG5cbiAgLy8gRG9lcyBhIGZpbmQgd2l0aCBcInNtYXJ0IGluZGV4aW5nXCIuXG4gIC8vIEN1cnJlbnRseSB0aGlzIGp1c3QgbWVhbnMsIGlmIGl0IG5lZWRzIGEgZ2VvaW5kZXggYW5kIHRoZXJlIGlzXG4gIC8vIG5vbmUsIHRoZW4gYnVpbGQgdGhlIGdlb2luZGV4LlxuICAvLyBUaGlzIGNvdWxkIGJlIGltcHJvdmVkIGEgbG90IGJ1dCBpdCdzIG5vdCBjbGVhciBpZiB0aGF0J3MgYSBnb29kXG4gIC8vIGlkZWEuIE9yIGV2ZW4gaWYgdGhpcyBiZWhhdmlvciBpcyBhIGdvb2QgaWRlYS5cbiAgZmluZChxdWVyeSwgeyBza2lwLCBsaW1pdCwgc29ydCwga2V5cywgbWF4VGltZU1TLCByZWFkUHJlZmVyZW5jZSB9ID0ge30pIHtcbiAgICAvLyBTdXBwb3J0IGZvciBGdWxsIFRleHQgU2VhcmNoIC0gJHRleHRcbiAgICBpZiAoa2V5cyAmJiBrZXlzLiRzY29yZSkge1xuICAgICAgZGVsZXRlIGtleXMuJHNjb3JlO1xuICAgICAga2V5cy5zY29yZSA9IHsgJG1ldGE6ICd0ZXh0U2NvcmUnIH07XG4gICAgfVxuICAgIHJldHVybiB0aGlzLl9yYXdGaW5kKHF1ZXJ5LCB7XG4gICAgICBza2lwLFxuICAgICAgbGltaXQsXG4gICAgICBzb3J0LFxuICAgICAga2V5cyxcbiAgICAgIG1heFRpbWVNUyxcbiAgICAgIHJlYWRQcmVmZXJlbmNlLFxuICAgIH0pLmNhdGNoKGVycm9yID0+IHtcbiAgICAgIC8vIENoZWNrIGZvciBcIm5vIGdlb2luZGV4XCIgZXJyb3JcbiAgICAgIGlmIChcbiAgICAgICAgZXJyb3IuY29kZSAhPSAxNzAwNyAmJlxuICAgICAgICAhZXJyb3IubWVzc2FnZS5tYXRjaCgvdW5hYmxlIHRvIGZpbmQgaW5kZXggZm9yIC5nZW9OZWFyLylcbiAgICAgICkge1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH1cbiAgICAgIC8vIEZpZ3VyZSBvdXQgd2hhdCBrZXkgbmVlZHMgYW4gaW5kZXhcbiAgICAgIGNvbnN0IGtleSA9IGVycm9yLm1lc3NhZ2UubWF0Y2goL2ZpZWxkPShbQS1aYS16XzAtOV0rKSAvKVsxXTtcbiAgICAgIGlmICgha2V5KSB7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfVxuXG4gICAgICB2YXIgaW5kZXggPSB7fTtcbiAgICAgIGluZGV4W2tleV0gPSAnMmQnO1xuICAgICAgcmV0dXJuIChcbiAgICAgICAgdGhpcy5fbW9uZ29Db2xsZWN0aW9uXG4gICAgICAgICAgLmNyZWF0ZUluZGV4KGluZGV4KVxuICAgICAgICAgIC8vIFJldHJ5LCBidXQganVzdCBvbmNlLlxuICAgICAgICAgIC50aGVuKCgpID0+XG4gICAgICAgICAgICB0aGlzLl9yYXdGaW5kKHF1ZXJ5LCB7XG4gICAgICAgICAgICAgIHNraXAsXG4gICAgICAgICAgICAgIGxpbWl0LFxuICAgICAgICAgICAgICBzb3J0LFxuICAgICAgICAgICAgICBrZXlzLFxuICAgICAgICAgICAgICBtYXhUaW1lTVMsXG4gICAgICAgICAgICAgIHJlYWRQcmVmZXJlbmNlLFxuICAgICAgICAgICAgfSlcbiAgICAgICAgICApXG4gICAgICApO1xuICAgIH0pO1xuICB9XG5cbiAgX3Jhd0ZpbmQocXVlcnksIHsgc2tpcCwgbGltaXQsIHNvcnQsIGtleXMsIG1heFRpbWVNUywgcmVhZFByZWZlcmVuY2UgfSA9IHt9KSB7XG4gICAgbGV0IGZpbmRPcGVyYXRpb24gPSB0aGlzLl9tb25nb0NvbGxlY3Rpb24uZmluZChxdWVyeSwge1xuICAgICAgc2tpcCxcbiAgICAgIGxpbWl0LFxuICAgICAgc29ydCxcbiAgICAgIHJlYWRQcmVmZXJlbmNlLFxuICAgIH0pO1xuXG4gICAgaWYgKGtleXMpIHtcbiAgICAgIGZpbmRPcGVyYXRpb24gPSBmaW5kT3BlcmF0aW9uLnByb2plY3Qoa2V5cyk7XG4gICAgfVxuXG4gICAgaWYgKG1heFRpbWVNUykge1xuICAgICAgZmluZE9wZXJhdGlvbiA9IGZpbmRPcGVyYXRpb24ubWF4VGltZU1TKG1heFRpbWVNUyk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGZpbmRPcGVyYXRpb24udG9BcnJheSgpO1xuICB9XG5cbiAgY291bnQocXVlcnksIHsgc2tpcCwgbGltaXQsIHNvcnQsIG1heFRpbWVNUywgcmVhZFByZWZlcmVuY2UgfSA9IHt9KSB7XG4gICAgLy8gSWYgcXVlcnkgaXMgZW1wdHksIHRoZW4gdXNlIGVzdGltYXRlZERvY3VtZW50Q291bnQgaW5zdGVhZC5cbiAgICAvLyBUaGlzIGlzIGR1ZSB0byBjb3VudERvY3VtZW50cyBwZXJmb3JtaW5nIGEgc2NhbixcbiAgICAvLyB3aGljaCBncmVhdGx5IGluY3JlYXNlcyBleGVjdXRpb24gdGltZSB3aGVuIGJlaW5nIHJ1biBvbiBsYXJnZSBjb2xsZWN0aW9ucy5cbiAgICAvLyBTZWUgaHR0cHM6Ly9naXRodWIuY29tL0F1dG9tYXR0aWMvbW9uZ29vc2UvaXNzdWVzLzY3MTMgZm9yIG1vcmUgaW5mbyByZWdhcmRpbmcgdGhpcyBwcm9ibGVtLlxuICAgIGlmICh0eXBlb2YgcXVlcnkgIT09ICdvYmplY3QnIHx8ICFPYmplY3Qua2V5cyhxdWVyeSkubGVuZ3RoKSB7XG4gICAgICByZXR1cm4gdGhpcy5fbW9uZ29Db2xsZWN0aW9uLmVzdGltYXRlZERvY3VtZW50Q291bnQoe1xuICAgICAgICBtYXhUaW1lTVMsXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBjb25zdCBjb3VudE9wZXJhdGlvbiA9IHRoaXMuX21vbmdvQ29sbGVjdGlvbi5jb3VudERvY3VtZW50cyhxdWVyeSwge1xuICAgICAgc2tpcCxcbiAgICAgIGxpbWl0LFxuICAgICAgc29ydCxcbiAgICAgIG1heFRpbWVNUyxcbiAgICAgIHJlYWRQcmVmZXJlbmNlLFxuICAgIH0pO1xuXG4gICAgcmV0dXJuIGNvdW50T3BlcmF0aW9uO1xuICB9XG5cbiAgZGlzdGluY3QoZmllbGQsIHF1ZXJ5KSB7XG4gICAgcmV0dXJuIHRoaXMuX21vbmdvQ29sbGVjdGlvbi5kaXN0aW5jdChmaWVsZCwgcXVlcnkpO1xuICB9XG5cbiAgYWdncmVnYXRlKHBpcGVsaW5lLCB7IG1heFRpbWVNUywgcmVhZFByZWZlcmVuY2UgfSA9IHt9KSB7XG4gICAgcmV0dXJuIHRoaXMuX21vbmdvQ29sbGVjdGlvblxuICAgICAgLmFnZ3JlZ2F0ZShwaXBlbGluZSwgeyBtYXhUaW1lTVMsIHJlYWRQcmVmZXJlbmNlIH0pXG4gICAgICAudG9BcnJheSgpO1xuICB9XG5cbiAgaW5zZXJ0T25lKG9iamVjdCwgc2Vzc2lvbikge1xuICAgIHJldHVybiB0aGlzLl9tb25nb0NvbGxlY3Rpb24uaW5zZXJ0T25lKG9iamVjdCwgeyBzZXNzaW9uIH0pO1xuICB9XG5cbiAgLy8gQXRvbWljYWxseSB1cGRhdGVzIGRhdGEgaW4gdGhlIGRhdGFiYXNlIGZvciBhIHNpbmdsZSAoZmlyc3QpIG9iamVjdCB0aGF0IG1hdGNoZWQgdGhlIHF1ZXJ5XG4gIC8vIElmIHRoZXJlIGlzIG5vdGhpbmcgdGhhdCBtYXRjaGVzIHRoZSBxdWVyeSAtIGRvZXMgaW5zZXJ0XG4gIC8vIFBvc3RncmVzIE5vdGU6IGBJTlNFUlQgLi4uIE9OIENPTkZMSUNUIFVQREFURWAgdGhhdCBpcyBhdmFpbGFibGUgc2luY2UgOS41LlxuICB1cHNlcnRPbmUocXVlcnksIHVwZGF0ZSwgc2Vzc2lvbikge1xuICAgIHJldHVybiB0aGlzLl9tb25nb0NvbGxlY3Rpb24udXBkYXRlT25lKHF1ZXJ5LCB1cGRhdGUsIHtcbiAgICAgIHVwc2VydDogdHJ1ZSxcbiAgICAgIHNlc3Npb24sXG4gICAgfSk7XG4gIH1cblxuICB1cGRhdGVPbmUocXVlcnksIHVwZGF0ZSkge1xuICAgIHJldHVybiB0aGlzLl9tb25nb0NvbGxlY3Rpb24udXBkYXRlT25lKHF1ZXJ5LCB1cGRhdGUpO1xuICB9XG5cbiAgdXBkYXRlTWFueShxdWVyeSwgdXBkYXRlLCBzZXNzaW9uKSB7XG4gICAgcmV0dXJuIHRoaXMuX21vbmdvQ29sbGVjdGlvbi51cGRhdGVNYW55KHF1ZXJ5LCB1cGRhdGUsIHsgc2Vzc2lvbiB9KTtcbiAgfVxuXG4gIGRlbGV0ZU1hbnkocXVlcnksIHNlc3Npb24pIHtcbiAgICByZXR1cm4gdGhpcy5fbW9uZ29Db2xsZWN0aW9uLmRlbGV0ZU1hbnkocXVlcnksIHsgc2Vzc2lvbiB9KTtcbiAgfVxuXG4gIF9lbnN1cmVTcGFyc2VVbmlxdWVJbmRleEluQmFja2dyb3VuZChpbmRleFJlcXVlc3QpIHtcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgdGhpcy5fbW9uZ29Db2xsZWN0aW9uLmNyZWF0ZUluZGV4KFxuICAgICAgICBpbmRleFJlcXVlc3QsXG4gICAgICAgIHsgdW5pcXVlOiB0cnVlLCBiYWNrZ3JvdW5kOiB0cnVlLCBzcGFyc2U6IHRydWUgfSxcbiAgICAgICAgZXJyb3IgPT4ge1xuICAgICAgICAgIGlmIChlcnJvcikge1xuICAgICAgICAgICAgcmVqZWN0KGVycm9yKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgKTtcbiAgICB9KTtcbiAgfVxuXG4gIGRyb3AoKSB7XG4gICAgcmV0dXJuIHRoaXMuX21vbmdvQ29sbGVjdGlvbi5kcm9wKCk7XG4gIH1cbn1cbiJdfQ==