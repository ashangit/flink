/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.table.operations.materializedtable;

import org.apache.flink.annotation.Internal;
import org.apache.flink.table.api.internal.TableResultInternal;
import org.apache.flink.table.catalog.CatalogMaterializedTable;
import org.apache.flink.table.catalog.ObjectIdentifier;
import org.apache.flink.table.catalog.TableChange.MaterializedTableChange;

import java.util.List;

/** Operation to describe an ALTER MATERIALIZED TABLE AS query operation. */
@Internal
public class AlterMaterializedTableAsQueryOperation extends AlterMaterializedTableOperation {

    private final List<MaterializedTableChange> tableChanges;

    private final CatalogMaterializedTable newMaterializedTable;

    public AlterMaterializedTableAsQueryOperation(
            ObjectIdentifier tableIdentifier,
            List<MaterializedTableChange> tableChanges,
            CatalogMaterializedTable newMaterializedTable) {
        super(tableIdentifier);
        this.tableChanges = tableChanges;
        this.newMaterializedTable = newMaterializedTable;
    }

    public List<MaterializedTableChange> getTableChanges() {
        return tableChanges;
    }

    public CatalogMaterializedTable getNewMaterializedTable() {
        return newMaterializedTable;
    }

    @Override
    public TableResultInternal execute(Context ctx) {
        throw new UnsupportedOperationException(
                "AlterMaterializedTableAsQueryOperation doesn't support ExecutableOperation yet.");
    }

    @Override
    public String asSummaryString() {
        return String.format(
                "ALTER MATERIALIZED TABLE %s AS %s",
                tableIdentifier.asSummaryString(), newMaterializedTable.getDefinitionQuery());
    }
}
