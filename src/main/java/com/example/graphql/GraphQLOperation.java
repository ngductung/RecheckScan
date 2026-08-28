package com.example.graphql;

import java.util.Set;
import java.util.TreeSet;

/**
 * Đại diện cho một "đơn vị theo dõi" của GraphQL: một root field bên trong một operation.
 * <p>
 * Trong REST, một API được định danh bởi (method, host, path). Với GraphQL thì hầu hết
 * request đều đi tới cùng một endpoint (ví dụ {@code /graphql}) nên URL path không còn
 * là thứ để phân biệt các "API" khác nhau. Thay vào đó, bề mặt tấn công thật sự của
 * GraphQL nằm ở:
 * <ul>
 *     <li>Loại operation: {@code query} / {@code mutation} / {@code subscription}</li>
 *     <li>Tên root field được gọi (ví dụ {@code user}, {@code createUser})</li>
 *     <li>Các argument của root field đó (bao gồm cả argument lồng bên trong) – đây chính
 *     là các "tham số" tương đương với query-param/body-param trong REST.</li>
 * </ul>
 * Vì vậy mỗi root field của mỗi operation được coi là một "API" độc lập để đánh dấu
 * đã-scan / chưa-scan, giống hệt tư duy của bản REST.
 */
public class GraphQLOperation {

    /** Loại operation: query, mutation hoặc subscription. */
    private final String operationType;

    /** Tên operation (ví dụ {@code GetUser}). Có thể rỗng với anonymous operation. */
    private final String operationName;

    /** Tên root field – định danh nghiệp vụ của "API" GraphQL này. */
    private final String rootField;

    /** Tập hợp tên tất cả argument (kể cả lồng nhau) thuộc root field – các injection point. */
    private final Set<String> argumentNames;

    public GraphQLOperation(String operationType, String operationName, String rootField, Set<String> argumentNames) {
        this.operationType = operationType;
        this.operationName = operationName == null ? "" : operationName;
        this.rootField = rootField;
        // Sắp xếp sẵn để dữ liệu ổn định khi so sánh / lưu trữ.
        this.argumentNames = new TreeSet<>(argumentNames == null ? Set.of() : argumentNames);
    }

    public String operationType() {
        return operationType;
    }

    public String operationName() {
        return operationName;
    }

    public String rootField() {
        return rootField;
    }

    public Set<String> argumentNames() {
        return argumentNames;
    }

    @Override
    public String toString() {
        return operationType + " " + rootField + " args=" + argumentNames;
    }
}
