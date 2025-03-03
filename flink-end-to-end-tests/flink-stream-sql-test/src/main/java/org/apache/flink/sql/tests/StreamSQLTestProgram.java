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

package org.apache.flink.sql.tests;

import org.apache.flink.api.common.functions.MapFunction;
import org.apache.flink.api.common.serialization.Encoder;
import org.apache.flink.api.common.state.ListState;
import org.apache.flink.api.common.state.ListStateDescriptor;
import org.apache.flink.api.common.typeinfo.TypeInformation;
import org.apache.flink.api.common.typeinfo.Types;
import org.apache.flink.api.common.typeutils.base.IntSerializer;
import org.apache.flink.api.common.typeutils.base.LongSerializer;
import org.apache.flink.api.java.typeutils.ResultTypeQueryable;
import org.apache.flink.api.java.typeutils.RowTypeInfo;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.configuration.RestartStrategyOptions;
import org.apache.flink.core.fs.Path;
import org.apache.flink.core.io.SimpleVersionedSerializer;
import org.apache.flink.runtime.state.FunctionInitializationContext;
import org.apache.flink.runtime.state.FunctionSnapshotContext;
import org.apache.flink.streaming.api.checkpoint.CheckpointedFunction;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.sink.filesystem.BucketAssigner;
import org.apache.flink.streaming.api.functions.sink.filesystem.bucketassigners.SimpleVersionedStringSerializer;
import org.apache.flink.streaming.api.functions.sink.filesystem.legacy.StreamingFileSink;
import org.apache.flink.streaming.api.functions.sink.filesystem.rollingpolicies.OnCheckpointRollingPolicy;
import org.apache.flink.streaming.api.functions.source.legacy.SourceFunction;
import org.apache.flink.table.api.DataTypes;
import org.apache.flink.table.api.Schema;
import org.apache.flink.table.api.Table;
import org.apache.flink.table.api.bridge.java.StreamTableEnvironment;
import org.apache.flink.types.Row;
import org.apache.flink.util.ParameterTool;

import java.io.PrintStream;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;

/**
 * End-to-end test for Stream SQL queries.
 *
 * <p>Includes the following SQL features: - OVER window aggregation - keyed and non-keyed GROUP BY
 * TUMBLE aggregation - windowed INNER JOIN - TableSource with event-time attribute
 *
 * <p>The stream is bounded and will complete after about a minute. The result is always constant.
 * The job is killed on the first attempt and restarted.
 *
 * <p>Parameters: -outputPath Sets the path to where the result data is written.
 */
public class StreamSQLTestProgram {

    public static void main(String[] args) throws Exception {

        ParameterTool params = ParameterTool.fromArgs(args);
        String outputPath = params.getRequired("outputPath");

        final StreamExecutionEnvironment sEnv =
                StreamExecutionEnvironment.getExecutionEnvironment();
        Configuration configuration = new Configuration();
        configuration.set(RestartStrategyOptions.RESTART_STRATEGY, "fixed-delay");
        configuration.set(RestartStrategyOptions.RESTART_STRATEGY_FIXED_DELAY_ATTEMPTS, 3);
        configuration.set(
                RestartStrategyOptions.RESTART_STRATEGY_FIXED_DELAY_DELAY, Duration.ofSeconds(10L));

        sEnv.configure(configuration);
        sEnv.enableCheckpointing(4000);
        sEnv.getConfig().setAutoWatermarkInterval(1000);

        final StreamTableEnvironment tEnv = StreamTableEnvironment.create(sEnv);

        final Schema tableSchema =
                Schema.newBuilder()
                        .column("key", DataTypes.INT())
                        .column("rowtime", DataTypes.TIMESTAMP(3).bridgedTo(Timestamp.class))
                        .column("payload", DataTypes.STRING())
                        .watermark("rowtime", "rowtime - interval '1' second")
                        .build();

        RowTypeInfo sourceType =
                new RowTypeInfo(
                        new TypeInformation[] {Types.INT, Types.SQL_TIMESTAMP, Types.STRING},
                        new String[] {"key", "rowtime", "payload"});
        DataStream<Row> source1 = sEnv.addSource(new Generator(10, 100, 60, 0), sourceType);
        tEnv.createTemporaryView("table1", source1, tableSchema);

        DataStream<Row> source2 = sEnv.addSource(new Generator(5, 0.2f, 60, 5), sourceType);
        tEnv.createTemporaryView("table2", source2, tableSchema);

        int overWindowSizeSeconds = 1;
        int tumbleWindowSizeSeconds = 10;

        String overQuery =
                String.format(
                        "SELECT "
                                + "  key, "
                                + "  rowtime, "
                                + "  COUNT(*) OVER (PARTITION BY key ORDER BY rowtime RANGE BETWEEN INTERVAL '%d' SECOND PRECEDING AND CURRENT ROW) AS cnt "
                                + "FROM table1",
                        overWindowSizeSeconds);

        String tumbleQuery =
                String.format(
                        "SELECT "
                                + "  key, "
                                + "  CASE SUM(cnt) / COUNT(*) WHEN 101 THEN 1 ELSE 99 END AS correct, "
                                + "  TUMBLE_START(rowtime, INTERVAL '%d' SECOND) AS wStart, "
                                + "  TUMBLE_ROWTIME(rowtime, INTERVAL '%d' SECOND) AS rowtime "
                                + "FROM (%s) "
                                + "WHERE rowtime > TIMESTAMP '1970-01-01 00:00:01' "
                                + "GROUP BY key, TUMBLE(rowtime, INTERVAL '%d' SECOND)",
                        tumbleWindowSizeSeconds,
                        tumbleWindowSizeSeconds,
                        overQuery,
                        tumbleWindowSizeSeconds);

        String joinQuery =
                String.format(
                        "SELECT "
                                + "  t1.key, "
                                + "  t2.rowtime AS rowtime, "
                                + "  t2.correct,"
                                + "  t2.wStart "
                                + "FROM table2 t1, (%s) t2 "
                                + "WHERE "
                                + "  t1.key = t2.key AND "
                                + "  t1.rowtime BETWEEN t2.rowtime AND t2.rowtime + INTERVAL '%d' SECOND",
                        tumbleQuery, tumbleWindowSizeSeconds);

        String finalAgg =
                String.format(
                        "SELECT "
                                + "  SUM(correct) AS correct, "
                                + "  TUMBLE_START(rowtime, INTERVAL '20' SECOND) AS rowtime "
                                + "FROM (%s) "
                                + "GROUP BY TUMBLE(rowtime, INTERVAL '20' SECOND)",
                        joinQuery);

        // get Table for SQL query
        Table result = tEnv.sqlQuery(finalAgg);
        // convert Table into append-only DataStream
        DataStream<Row> resultStream =
                tEnv.toDataStream(
                        result,
                        DataTypes.ROW(
                                DataTypes.INT(), DataTypes.TIMESTAMP().bridgedTo(Timestamp.class)));

        final StreamingFileSink<Row> sink =
                StreamingFileSink.forRowFormat(
                                new Path(outputPath),
                                (Encoder<Row>)
                                        (element, stream) -> {
                                            PrintStream out = new PrintStream(stream);
                                            out.println(element.toString());
                                        })
                        .withBucketAssigner(new KeyBucketAssigner())
                        .withRollingPolicy(OnCheckpointRollingPolicy.build())
                        .build();

        resultStream
                // inject a KillMapper that forwards all records but terminates the first execution
                // attempt
                .map(new KillMapper())
                .setParallelism(1)
                // add sink function
                .addSink(sink)
                .setParallelism(1);

        sEnv.execute();
    }

    /** Use first field for buckets. */
    public static final class KeyBucketAssigner implements BucketAssigner<Row, String> {

        private static final long serialVersionUID = 987325769970523326L;

        @Override
        public String getBucketId(final Row element, final Context context) {
            return String.valueOf(element.getField(0));
        }

        @Override
        public SimpleVersionedSerializer<String> getSerializer() {
            return SimpleVersionedStringSerializer.INSTANCE;
        }
    }

    /** Data-generating source function. */
    public static class Generator
            implements SourceFunction<Row>, ResultTypeQueryable<Row>, CheckpointedFunction {

        private final int numKeys;
        private final int offsetSeconds;

        private final int sleepMs;
        private final int durationMs;

        private long ms = 0;
        private ListState<Long> state = null;

        public Generator(
                int numKeys, float rowsPerKeyAndSecond, int durationSeconds, int offsetSeconds) {
            this.numKeys = numKeys;
            this.durationMs = durationSeconds * 1000;
            this.offsetSeconds = offsetSeconds;

            this.sleepMs = (int) (1000 / rowsPerKeyAndSecond);
        }

        @Override
        public void run(SourceContext<Row> ctx) throws Exception {
            long offsetMS = offsetSeconds * 2000L;

            while (ms < durationMs) {
                synchronized (ctx.getCheckpointLock()) {
                    for (int i = 0; i < numKeys; i++) {
                        ctx.collect(
                                Row.of(
                                        i,
                                        Timestamp.from(Instant.ofEpochMilli(ms + offsetMS)),
                                        "Some payload..."));
                    }
                    ms += sleepMs;
                }
                Thread.sleep(sleepMs);
            }
        }

        @Override
        public void cancel() {}

        @Override
        public TypeInformation<Row> getProducedType() {
            return Types.ROW(Types.INT, Types.SQL_TIMESTAMP, Types.STRING);
        }

        @Override
        public void initializeState(FunctionInitializationContext context) throws Exception {
            state =
                    context.getOperatorStateStore()
                            .getListState(
                                    new ListStateDescriptor<Long>(
                                            "state", LongSerializer.INSTANCE));

            for (Long l : state.get()) {
                ms += l;
            }
        }

        @Override
        public void snapshotState(FunctionSnapshotContext context) throws Exception {
            state.update(Collections.singletonList(ms));
        }
    }

    /** Kills the first execution attempt of an application when it receives the second record. */
    public static class KillMapper
            implements MapFunction<Row, Row>, CheckpointedFunction, ResultTypeQueryable {

        // counts all processed records of all previous execution attempts
        private int saveRecordCnt = 0;
        // counts all processed records of this execution attempt
        private int lostRecordCnt = 0;

        private ListState<Integer> state = null;

        @Override
        public Row map(Row value) {

            // the both counts are the same only in the first execution attempt
            if (saveRecordCnt == 1 && lostRecordCnt == 1) {
                throw new RuntimeException("Kill this Job!");
            }

            // update checkpointed counter
            saveRecordCnt++;
            // update non-checkpointed counter
            lostRecordCnt++;

            // forward record
            return value;
        }

        @Override
        public TypeInformation getProducedType() {
            return Types.ROW(Types.INT, Types.SQL_TIMESTAMP);
        }

        @Override
        public void initializeState(FunctionInitializationContext context) throws Exception {
            state =
                    context.getOperatorStateStore()
                            .getListState(
                                    new ListStateDescriptor<Integer>(
                                            "state", IntSerializer.INSTANCE));

            for (Integer i : state.get()) {
                saveRecordCnt += i;
            }
        }

        @Override
        public void snapshotState(FunctionSnapshotContext context) throws Exception {
            state.update(Collections.singletonList(saveRecordCnt));
        }
    }
}
