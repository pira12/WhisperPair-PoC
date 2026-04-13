import { io } from 'socket.io-client';

const socket = io('/', {
  transports: ['websocket', 'polling'],
  autoConnect: true,
});

export default socket;
