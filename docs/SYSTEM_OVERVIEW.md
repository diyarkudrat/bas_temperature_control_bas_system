# BAS System Overview & Architecture

**Complete system architecture and design guide for the Building Automation System (BAS) temperature controller.**

---

## 🏗️ System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BAS Temperature Controller                        │
│                        Raspberry Pi Pico W + MicroPython                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
            ┌───────▼───────┐ ┌─────▼─────┐ ┌──────▼──────┐
            │   Hardware    │ │  Control   │ │   Network   │
            │   Abstraction │ │   Logic    │ │   Services  │
            └───────────────┘ └───────────┘ └─────────────┘
                    │               │               │
            ┌───────▼───────┐ ┌─────▼─────┐ ┌──────▼──────┐
            │ • DS18B20     │ │ • FSM     │ │ • WiFi      │
            │ • Relays      │ │ • Hyster. │ │ • HTTP API  │
            │ • OLED        │ │ • Safety  │ │ • SSE       │
            │ • I2C/1-Wire  │ │ • Timing  │ │ • Auth      │
            └───────────────┘ └───────────┘ └─────────────┘
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                            ┌───────▼───────┐
                            │   System      │
                            │ Orchestrator  │
                            │  (main.py)    │
                            └───────────────┘
                                    │
                            ┌───────▼───────┐
                            │   Services    │
                            │ • Config      │
                            │ • Logging     │
                            │ • Telemetry   │
                            │ • Error Mgmt  │
                            └───────────────┘
```

---

## 🔄 Control Loop Flow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Temperature   │───▶│   Controller    │───▶│    Actuators    │
│    Sensor       │    │   (FSM Logic)   │    │   (Relays)      │
│   (DS18B20)     │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         ▲                       │                       │
         │                       │                       │
         │              ┌────────▼────────┐              │
         │              │  Hysteresis &   │              │
         │              │ Anti-short-cycle │              │
         │              │   Protection    │              │
         │              └─────────────────┘              │
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Safety & Fault       │
                    │      Handling           │
                    └─────────────────────────┘
```

---

## 📊 Data Flow Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Hardware      │    │   Application   │    │   Network       │
│   Layer         │    │   Layer         │    │   Layer         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ • DS18B20       │    │ • Controller    │    │ • HTTP Server   │
│ • Relay GPIO    │    │ • Display       │    │ • WebSocket     │
│ • OLED I2C      │    │ • Telemetry     │    │ • REST API      │
│ • WiFi Module   │    │ • Config Mgmt   │    │ • Authentication│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Interfaces    │    │   Services      │    │   Clients        │
│   (Abstraction) │    │   (Business)     │    │   (External)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

---

## 🧩 Component Architecture

### **Core Components**

```
┌─────────────────────────────────────────────────────────────────┐
│                        System Orchestrator                      │
│                           (main.py)                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐ │
│  │ Controller  │  │   Display   │  │   Network   │  │Telemetry │ │
│  │             │  │             │  │             │  │          │ │
│  │ • FSM Logic │  │ • OLED      │  │ • WiFi      │  │ • Buffer │ │
│  │ • Hysteresis│  │ • Status    │  │ • HTTP API  │  │ • Export │ │
│  │ • Safety    │  │ • Icons     │  │ • Auth      │  │ • Stats  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### **Hardware Abstraction Layer**

```
┌─────────────────────────────────────────────────────────────────┐
│                    Hardware Abstraction Layer                   │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐ │
│  │ Temperature │  │  Actuators  │  │   Display   │  │  Clock   │ │
│  │   Sensor    │  │             │  │             │  │          │ │
│  │             │  │ • Cooling   │  │ • OLED      │  │ • Timing │ │
│  │ • DS18B20   │  │ • Heating   │  │ • Status    │  │ • Sleep  │ │
│  │ • 1-Wire    │  │ • GPIO      │  │ • I2C       │  │ • Elapse │ │
│  │ • Fault Det │  │ • Safety    │  │ • Graphics  │  │ • Utils  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### **Service Layer**

```
┌─────────────────────────────────────────────────────────────────┐
│                         Service Layer                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐ │
│  │   Config    │  │   Logging   │  │    Error    │  │Telemetry │ │
│  │ Management  │  │             │  │  Handling   │  │          │ │
│  │             │  │ • Levels    │  │             │  │ • Points │ │
│  │ • Profiles  │  │ • Buffers   │  │ • Recovery  │  │ • Export │ │
│  │ • Secrets   │  │ • Context   │  │ • Stats     │  │ • Health │ │
│  │ • Runtime   │  │ • Factory   │  │ • Critical  │  │ • CSV    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔧 System Design Principles

### **1. Clean Architecture**
- **Dependency Injection**: Hardware components injected into controllers
- **Interface Segregation**: Clear contracts between layers
- **Single Responsibility**: Each component has one clear purpose

### **2. MicroPython Constraints**
- **Memory Efficiency**: Ring buffers, slot classes, minimal allocations
- **Non-blocking**: Cooperative scheduling, no threading
- **Resource Management**: Explicit cleanup and resource tracking

### **3. Production Readiness**
- **Fault Tolerance**: Graceful degradation, fail-safe states
- **Observability**: Comprehensive logging and telemetry
- **Security**: Authentication, input validation, rate limiting

### **4. Extensibility**
- **Plugin Architecture**: Custom collectors, backends, sensors
- **Configuration Profiles**: Environment-specific settings
- **API-First**: RESTful endpoints for all operations

---

## 🚀 System Startup Sequence

```
1. Hardware Initialization
   ├── GPIO Configuration
   ├── I2C/1-Wire Setup
   └── Sensor Detection

2. Service Initialization
   ├── Configuration Loading
   ├── Logging Setup
   └── Error Handler Registration

3. Network Setup
   ├── WiFi Connection
   ├── HTTP Server Start
   └── API Route Registration

4. Control Loop Start
   ├── Controller Initialization
   ├── Display Initialization
   └── Telemetry Collection

5. Runtime Operation
   ├── Cooperative Scheduling
   ├── Event Processing
   └── Health Monitoring
```

---

## 🔒 Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Security Layers                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐ │
│  │   Network   │  │Application  │  │    Data     │  │  System   │ │
│  │   Security  │  │  Security   │  │  Security   │  │ Security  │ │
│  │             │  │             │  │             │  │           │ │
│  │ • Rate Limit│  │ • Auth      │  │ • Secrets   │  │ • Hooks   │ │
│  │ • Timeouts  │  │ • Sessions  │  │ • Hashing   │  │ • Validation│
│  │ • Headers   │  │ • MFA       │  │ • Encryption│  │ • Audit   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🧪 Testing Architecture

### **Test Pyramid**
```
        ┌─────────────────┐
        │  Integration    │  ← End-to-end system tests
        │     Tests       │
        └─────────────────┘
       ┌─────────────────────┐
       │   Performance       │  ← Load, stress, timing tests
       │      Tests          │
       └─────────────────────┘
    ┌───────────────────────────┐
    │        Unit Tests         │  ← Component isolation tests
    └───────────────────────────┘
```

### **Test Categories**
- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing
- **Performance Tests**: Timing and memory validation
- **Security Tests**: Authentication and input validation
- **Hardware Tests**: Sensor and actuator validation

---

## 🔄 Data Flow Summary

1. **Sensor Reading** → Temperature data from DS18B20
2. **Controller Logic** → FSM decision based on hysteresis
3. **Actuator Control** → Relay activation/deactivation
4. **Display Update** → OLED status visualization
5. **Telemetry Collection** → Data point storage
6. **Network Services** → API responses and SSE events
7. **Configuration** → Runtime parameter updates
8. **Logging** → Event and error tracking

---

## 🎯 System Goals

### **Primary Objectives**
- ✅ **Reliable Temperature Control** - Precise, stable temperature regulation
- ✅ **Production Ready** - Robust, fault-tolerant operation
- ✅ **Easy Integration** - Simple API and configuration
- ✅ **Extensible** - Support for additional sensors and features

### **Technical Goals**
- ✅ **MicroPython Compatible** - Runs on Pico W constraints
- ✅ **Memory Efficient** - Minimal resource usage
- ✅ **Non-blocking** - Cooperative scheduling
- ✅ **Secure** - Authentication and input validation

### **Operational Goals**
- ✅ **Maintainable** - Clean code and documentation
- ✅ **Testable** - Comprehensive test coverage
- ✅ **Observable** - Rich logging and telemetry
- ✅ **Configurable** - Flexible runtime settings

---

This system overview provides a complete understanding of the BAS architecture, from high-level system design to low-level implementation details. Use this guide to understand how all components work together to create a production-grade temperature control system.
